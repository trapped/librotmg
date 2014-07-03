#!/usr/bin/ruby
require 'parslet'
require 'pp'
require 'colorize'

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

def scan_rsa(pkt)
	res = []
	pkt[:inline].each do |line|
		if line[:type].first[0] == :binary && line[:opts] && line[:opts][:opt] == "rsa"
			res << line[:var].to_s
		end
	end
	return res
end

def gen_strtopkt(pkt)
	rsa_scan = scan_rsa pkt

	i = 0

	ppp i, "rotmg_packet*"
	ppp i, "rotmg_strtopkt_#{pkt[:hpkt].to_s.reverse.chomp('rotmg_packet_'.reverse).reverse} (" +
		   "#{pkt[:hpkt].to_s}* str#{rsa_scan.length > 0 ? ", rsa_util* rsa" : ''}) {"

	i += 1

	if rsa_scan.length > 0
		ppp i, "//rsa encrypted data length"
		ppp i, "short encrypted_length = (short)get_modulus_bytes(rsa->pub_key_rsa);"
	end

	pkt[:inline].each do |line|

		type = line[:type].first[0]

		if rsa_scan.include? line[:var].to_s

			ppp i, "//encrypted #{line[:var].to_s} to base64"

			ppp i, ["unsigned char*",
					"temp_encrypted_#{line[:var].to_s}", "=",
					"(unsigned char*)pub_encrypt",
					"(str->#{line[:var].to_s},",
					"str->#{line[:var].to_s}_length, rsa)"].join(' ') + ";"

			ppp i, ["unsigned char*",
					"encrypted_#{line[:var].to_s}", "=",
					"(unsigned char*)b64_enc",
					"((int)encrypted_length,",
					"temp_encrypted_#{line[:var].to_s})"].join(' ') + ";"

			ppp i, "free(temp_encrypted_#{line[:var].to_s};"


			ppp i, "//encrypted #{line[:var].to_s} length"

			ppp i, ["unsigned char*",
					"temp_encrypted_#{line[:var].to_s}_length", "=",
					"#{typeconv[:short]}",
					"(strlen((char*)encrypted_#{line[:var].to_s}))"].join(' ') + ";"

			ppp i, ["unsigned char*",
					"encrypted_#{line[:var].to_s}_length", "=",
					"reverse_endian(#{typesize[:short]}",
					"temp_encrypted_#{line[:var].to_s})"].join(' ') + ";"

			ppp i, "free(temp_encrypted_#{line[:var].to_s});"

		elsif [:short, :long].include?(type) && !rsa_scan.include?(line[:var].to_s.chomp '_length')

			ppp i, "//#{line[:var].to_s.tr '_', ' '}"

			ppp i, ["unsigned char*",
					"temp_#{line[:var].to_s}", "=",
					"#{typeconv[type]}",
					"(str->#{line[:var].to_s})"].join(' ') + ";"

			ppp i, ["unsigned char*",
					"#{line[:var].to_s}", "=",
					"reverse_endian(#{typesize[type]},",
					"temp_#{line[:var].to_s})"].join(' ') + ";"

			ppp i, "free(temp_#{line[:var].to_s});"

		end
	end
	i = 0
	ppp i, '}'
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

str = parse ARGF.read
ana = analyze str
if ana.length > 0
	puts ana
else
	gen_strtopkt str
end
