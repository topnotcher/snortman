class String
	def msplit(split,meta)
		toks = []
		cur_tok = ''
		self.split(split).each do |tok|
			if tok.end_with? meta
				cur_tok += tok[0,tok.size-2]
			else
				cur_tok += tok
				toks << cur_tok
				cur_tok = ''
			end
		end

		return toks
	end
end

str = 'alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"GPL ICMP Time-To-Live Exceeded in Transit undefined code"; icode:>1; itype:11; classtype:misc-activity; sid:2100450; rev:9;)';


hdr_cols = [:action, :proto, :src, :sport, :dir, :dst, :dport]
toks = str.split(' ', 8)
raise 'bad rule [toks < 8]' if toks.size < 8

opt = toks[7]
rule = Hash[hdr_cols.zip(toks[0,7])]
puts rule
raise "missing source port in rule" if ['<>','->'].include? rule[:sport]
raise "missing destination port in rule" if rule[:dport] =~ /^\(/
opt.strip!

raise 'the rule option section (starting with a \'(\') must follow immediately after the destination port.' unless opt =~ /^\(.+/
raise 'missing trailing ) in rule' unless opt =~ /.+\)$/

opt.sub!(/^\((.+)\)$/,'\1')
optsa = opt.msplit(';','\\')

raise 'empty options list in rule' if optsa.size == 0
raise 'too many options in rule' if optsa.size > 256

puts optsa


