#!/usr/bin/ruby
require 'parslet'
require 'pp'
require 'colorize'

#
# Code parsing
#
class Str < Parslet::Parser
	rule(:s)       { match('\s').repeat 1                                                                                                 }
	rule(:short)   { str('short').as(:short)                                                                                              }
	rule(:long)    { str('long').as(:long)                                                                                                }
	rule(:binary)  { str('unsigned char*').as(:binary)                                                                                    }
	rule(:type)    { short | long | binary                                                                                                }
	rule(:name)    { match('[a-zA-Z_]') >> match('[a-zA-Z0-9_]').repeat                                                                   }
	rule(:opts)    { str('///') >> str('rsa').as(:opt) >> s.maybe                                                                           }
	rule(:inline)  { s.maybe >> type.as(:type) >> s >> name.as(:var) >> s.maybe >> str(';') >> s.maybe >> opts.maybe.as(:opts) >> s.maybe }
	rule(:header)  { str('typedef') >> s >> str('struct') >> s >> name.as(:hpkt) >> s.maybe >> str('{') >> s.maybe                        }
	rule(:footer)  { s.maybe >> str('}') >> s.maybe >> name.as(:fpkt) >> s.maybe >> str(';')                                              }
	rule(:code)    { s.maybe >> header >> inline.repeat(1).as(:inline) >> footer >> s.maybe                                               }
	root :code
end

def parse(str)
	uct = Str.new
	uct.parse str
rescue Parslet::ParseFailed => failure
	puts "#{failure.cause.ascii_tree}".red
	exit 1
end

#
# Utilities
#
def ppp(i, str)
	print "#{"\t" * i}#{str}\n"
end

def typesize
	{
		:short => 2,
		:long => 4
	}
end

def typeconv
	{
		:short => "stoc",
		:long => "ltoc"
	}
end

#
# Static analyzers
#
def scan_rsa(pkt)
	res = []
	pkt[:inline].each do |line|
		if line[:type].first[0] == :binary && line[:opts] && line[:opts][:opt] == "rsa"
			res << line[:var].to_s
		end
	end
	return res
end

def scan_longs(pkt)
	res = []
	pkt[:inline].each do |line|
		res << line[:var].to_s if line[:type].first[0] == :long
	end
	return res
end

def scan_shorts(pkt)
	res = []
	pkt[:inline].each do |line|
		res << line[:var].to_s if line[:type].first[0] == :short
	end
	return res
end

def analyze(pkt)
	res = []
	
	if pkt[:hpkt].to_s != pkt[:fpkt].to_s
		res << "Struct names do not match:".red
		res << "\ttypedef struct #{pkt[:hpkt].to_s.red} {"
		res << "\t\t[...]"
		res << "\t} #{pkt[:fpkt].to_s.red};"
	end

	binaries = 0
	lengths = 0
	pkt[:inline].each do |line|
		type = line[:type].first[0]
		if type == :binary
			binaries += 1
		elsif [:short, :long].include? type and line[:var].to_s.end_with? '_length'
			lengths += 1
		end
	end

	if binaries != lengths
		res << (binaries > lengths ? "#{binaries - lengths} binary field(s) length missing".red : "#{lengths - binaries} unused length fields".yellow)
	end

	return res.join "\n"
end

#
# Code generators
#
def gen_headers(rsa=false)
	base = ['<stdlib.h>', '<string.h>']
	rsa = ['<openssl/bio.h>', '<openssl/evp.h>', '"../rsa.h"']
	external = ['"../utils.h"',	'"../rotmg.h"', '"../packet_ids.h"']

	base.each { |h|	ppp 0, "\#include #{h}"	}

	# two-pass since rsa.h should not be in /usr/include
	rsa.each { |h| ppp 0, "\#include #{h}" if h[0] == '<' } if rsa

	external.each { |h| ppp 0, "\#include #{h}" }

	rsa.each { |h| ppp 0, "\#include #{h}" if h[0] == '"' } if rsa
end

def gen_rsa_modsize(rsa)
	if rsa.length > 0
		ppp 1, "//rsa encrypted data length"
		ppp 1, "short encrypted_length = (short)get_modulus_bytes(rsa->pub_key_rsa);"
	end
end

def gen_rsa_encrypt(var)
	ppp 1, "//encrypted #{var} to base64"

	# encrypt to rsa
	ppp 1, ["unsigned char*",
			"temp_encrypted_#{var}", "=",
			"(unsigned char*)pub_encrypt",
			"(str->#{var},",
			"str->#{var}_length, rsa)"].join(' ') + ";"

	# encode to base64
	ppp 1, ["unsigned char*",
			"encrypted_#{var}", "=",
			"(unsigned char*)b64_enc",
			"((int)encrypted_length,",
			"temp_encrypted_#{var})"].join(' ') + ";"

	# free temporary non-base64 data
	ppp 1, "free(temp_encrypted_#{var};"


	ppp 1, "//encrypted #{var} length"

	# convert rsa modulus length to bytes
	ppp 1, ["unsigned char*",
			"temp_encrypted_#{var}_length", "=",
			"#{typeconv[:short]}",
			"(strlen((char*)encrypted_#{var}))"].join(' ') + ";"

	# reverse endianness
	ppp 1, ["unsigned char*",
			"encrypted_#{var}_length", "=",
			"reverse_endian(#{typesize[:short]}",
			"temp_encrypted_#{var})"].join(' ') + ";"

	# free temporary length bytes
	ppp 1, "free(temp_encrypted_#{var});"
end

def gen_num_expand(type, var)
	ppp 1, "//#{var.tr '_', ' '}"

	# convert value to bytes
	ppp 1, ["unsigned char*",
			"temp_#{var}", "=",
			"#{typeconv[type]}",
			"(str->#{var})"].join(' ') + ";"

	# reverse endianness
	ppp 1, ["unsigned char*",
			"#{var}", "=",
			"reverse_endian(#{typesize[type]},",
			"temp_#{var})"].join(' ') + ";"

	# free temporary dat
	ppp 1, "free(temp_#{var});"
end

def gen_pkt_alloc(pkt)
	ppp 1, "rotmg_packet* pkt = calloc(1, sizeof(rotmg_packet));"
	ppp 1, "if(!pkt) {"
	ppp 2, 'puts("couldn\'t allocate memory for an ' +
		pkt[:hpkt].to_s.reverse.chomp('rotmg_packet_'.reverse).reverse +
		' packet");'
	ppp 2, 'return NULL;'
	ppp 1, "}"
end

def gen_payload_alloc(pkt)
	ppp 1, "pkt->payload = calloc(1, size);"
	ppp 1, "if(!pkt->payload) {"
	ppp 2, 'puts("couldn\'t allocate memory for an ' +
		pkt[:hpkt].to_s.reverse.chomp('rotmg_packet_'.reverse).reverse +
		' packet\'s payload");'
	ppp 1, "}"
end

def gen_pkt_size(pkt)
	if pkt[:inline].length > 0
		rsa = scan_rsa pkt
		shorts = scan_shorts pkt
		longs = scan_longs pkt

		ppp 1, "long size = (sizeof(short)*#{shorts.length})+(sizeof(long)*#{longs.length})+"

		i = 0
		rsa.each do |l|
			shorts.delete("#{l}_length")
			longs.delete("#{l}_length")
			ppp 4, "(sizeof(char)*strlen((char*)encrypted_#{l}))#{(shorts + longs).length > 0 && i != rsa.length-1 ? '+' : ';'}"
			i += 1
		end

		i = 0
		(shorts + longs).each do |l|
			ppp 4, "(sizeof(char)*str->#{l}_length)#{(shorts + longs).length != i - 1 ? '+' : ';'}"
		end
	end
end

def gen_strtopkt(rsa, pkt)
	ppp 0, "rotmg_packet*"
	ppp 0, "rotmg_strtopkt_#{pkt[:hpkt].to_s.reverse.chomp('rotmg_packet_'.reverse).reverse} (" +
		   "#{pkt[:hpkt].to_s}* str#{rsa.length > 0 ? ", rsa_util* rsa" : ''}) {"

	gen_rsa_modsize rsa

	# preparation (value to binary conversion)
	pkt[:inline].each do |line|

		type = line[:type].first[0]

		# needs rsa encryption?
		if rsa.include? line[:var].to_s

			gen_rsa_encrypt line[:var].to_s

		# make sure it's not an rsa-encrypted field's length
		elsif [:short, :long].include?(type) && !rsa.include?(line[:var].to_s.chomp '_length')

			gen_num_expand type, line[:var].to_s

		end
	end

	ppp 0, ""

	# allocate memory for the packet
	gen_pkt_alloc pkt

	ppp 0, ""

	# compose packet size
	gen_pkt_size pkt

	# allocate memory for packet payload
	gen_payload_alloc pkt

	ppp 0, '}'
end

def codegen(str, pkt)
	# check if rsa is used
	rsa = scan_rsa pkt

	# include headers
	gen_headers rsa.length > 0

	# add original struct
	puts "\n#{str}\n"

	# serialization
	gen_strtopkt rsa, pkt
end

str = ARGF.read
pkt = parse str
ana = analyze pkt
if ana.length > 0
	puts ana
else
	codegen str, pkt
end
