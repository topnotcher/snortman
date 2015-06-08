require 'pp'

class String
	# msplit is like split, but allows escaping the split character with
	# a meta character, e.g. \.
	def msplit(split,meta,max=nil)
		toks = []
		cur_tok = ''
		self.split(split).each do |tok|
			if tok.end_with? meta
				cur_tok += tok+split
			else
				cur_tok += tok
				if max and toks.size >= max
					toks[toks.size-1] += split+cur_tok
				else
					toks << cur_tok
				end
				cur_tok = ''
			end
		end

		return toks
	end
end


# Parse rules from a single file
class RuleFileParser

	def parse_file(name)
		filename = File.basename(name)
		rule = ''
		n = 0
		start_line = nil
		rules = {}
		File.open(name).each_line do |line|
			n+=1
			line.strip!
			next if line.start_with? '#'
			next if line.size < 1

			start_line ||= n

			rule += line

			if rule.end_with? '\\'
				rule.chomp! '\\'
				next
			end

			begin
				parsed = parse_rule(rule)
				parsed[:meta] = {file: filename, enabled: true, raw: rule}
				rules[parsed[:opts][:sid]] = parsed
			rescue Exception => e
				raise "parse error in %s on lines %d-%d: %s" % [name, start_line,n,e.message]
			end

			start_line = nil
			rule = ''
		end
		return rules
	end

	def parse_rule(str)

		hdr_cols = [:action, :proto, :src, :sport, :dir, :dst, :dport]
		toks = str.split(' ', 8)
		raise 'bad rule [toks < 8]' if toks.size < 8

		opt = toks[7]
		rule = Hash[hdr_cols.zip(toks[0,7])]

		raise "missing source port in rule" if ['<>','->'].include? rule[:sport]
		raise "missing destination port in rule" if rule[:dport] =~ /^\(/
		opt.strip!

		raise 'the rule option section (starting with a \'(\') must follow immediately after the destination port.' unless opt =~ /^\(.+/
		raise 'missing trailing ) in rule' unless opt =~ /.+\)$/

		opt.sub!(/^\((.+)\)$/,'\1')
		return rule.merge parse_opts(opt)
	end

	def parse_opts(opt_sect)
		optsa = opt_sect.msplit(';','\\')

		raise 'empty options list in rule' if optsa.size == 0
		raise 'too many options in rule' if optsa.size > 256

		ret = {}
		idx_opts = [:msg, :classtype, :sid, :rev, :reference, :flow, :flowbits]
		req_opts = [:msg ,:sid]
		agg_opts = [:reference, :flowbits]
		many_opts = [:reference, :flowbits]


		optsa.each do |opt|
			opt.strip!

			key,value = opt.msplit(':','\\',2)

			key = key.to_sym

			value.sub!(/^"(.*)"$/, '\1') unless value.nil?
			value = value.to_i if key == :sid

			if !idx_opts.include? key
				ret[:raw] ||= []
				ret[:raw] << {key => value}
			elsif agg_opts.include? key
				ret[key] ||= []
				ret[key] << value
			elsif !many_opts.include? key and ret[key]
				raise 'There can only be one %s' % [key]
			elsif
				ret[key] = value
			end
		end

		req_opts.each do |key|
			raise "missing required option %s" % [key] unless ret[key]
		end

		parse_flowbits(ret)

		return {opts: ret}
	end

	def parse_flowbits(opts)
		return unless opts[:flowbits]

		rulebits = {'set' => [], 'unset' => [], 'isset' => [], 'noalert' => false,'isnotset' => []}
		opts[:flowbits].each do |str|
			act,bit = str.split(',',2)
			act.strip!# bit.strip!
			if act != 'noalert'
				rulebits[act] << bit
			else
				rulebits['noalert'] = true
			end
		end

		opts[:flowbits] = rulebits
	end
end

class RuleWriter
	attr_accessor :rules
	def write(rule)
		opt_string = write_opt_str rule[:opts]
		header = write_header rule
		"%s (%s)" % [header, opt_string]
	end

	def write_header(rule)
		'%s %s %s %s %s %s %s' % [rule[:action], rule[:proto], rule[:src],
			rule[:sport], rule[:dir], rule[:dst], rule[:dport]]
	end

	def write_opt_str(opts)
		opt_array = []

		opts.each_pair do |key,value|
			next if key == :raw
			opt_array += reassemble_opt(key,value)
		end

		opt_array += get_raw_opts opts[:raw]

		opt_array.join ' '
	end

	def fmt_opt(key,value)
		if value.nil?
			"#{key.to_s};"
		elsif [:msg, :pcre, :content, :uricontent].include? key and (not value.end_with?('"') or value.end_with?('\\"'))
			'%s:"%s";' % [key.to_s,value]
		else
			'%s:%s;' % [key.to_s,value]
		end
	end

	def reassemble_opt(key,value)
		opts = []
		value = value.to_s if value.kind_of? Fixnum

		if value.kind_of? String
			opts << fmt_opt(key,value)
		elsif key == :flowbits
			opts += reassmble_flowbits(value)
		# now assume it's an array...
		else
			value.each do |str|
				opts << fmt_opt(key,str)
			end
		end

		opts
	end

	def reassmble_flowbits(value)
		opts = []
		value.each_pair do |act,bits|
			next if act == 'noalert'
			bits.each {|bit| opts << 'flowbits:%s,%s;' % [act,bit]}
		end
		opts << 'flowbits:noalert;' if value['noalert']

		opts
	end

	def get_raw_opts(raw)
		return [] unless raw
		opts = []
		raw.each do |opt|
			opt.each_pair {|key,value| opts << fmt_opt(key,value) }
		end

		return opts
	end

	def resolve_rule_priority(rule)
		# this is a bit hilarious to run this every fucking time
		# eh whole thing is dirty as fuck right now anyway
		classification = get_classification

		if !rule[:opts][:priority]
			if rule[:opts][:classtype] and classification.has_key? rule[:opts][:classtype]
				priority = classification[rule[:opts][:classtype]]['priority']
			else
				priority = 1
			end
		else
			priority = rule[:opts][:priority]
		end

		return priority
	end

	def write_sid_map(rule)
		priority = resolve_rule_priority(rule)

		# prevent barnyard parse errors when this is not specified
		rule[:opts][:classtype] ||= 'bad-unknown'

		map = "%d || %s || %s || %s || %d || %s" % [1, rule[:opts][:sid], rule[:opts][:rev],rule[:opts][:classtype], priority, rule[:opts][:msg]]
		map += ' || ' + rule[:opts][:reference].join(' || ') if rule[:opts][:reference]
		return map
	end

	# @TODO!!!
	def get_classification
		classification = {}
		File.open('rules/classification.config').each_line do |line|
			line.sub!(/(.*)#.*/,'\1')
			line.strip!

			next if line.size == 0

			pcs = line.scan(/classification:([^,]+),([^,]+),(.+)/)

			next if pcs.size != 1
			class_data = pcs[0]
			class_data.each {|pc| pc.strip!}

			classification[class_data[0]] = {'description' => class_data[1], 'priority' => class_data[2]}
		end
		return classification
	end
end

class RulesManager
	attr_accessor :rules
	def initialize
		@flowbits = {}
		@rules = {}
	end

	def index_flowbits(rule)
		return unless rule[:opts][:flowbits]

		rule[:opts][:flowbits].each_pair do |act,bits|
			next if act == 'noalert'
			bits.each do |bit|
				@flowbits[bit] ||= {'set' => [], 'unset' => [], 'isset' => [], 'isnotset' => []}
				@flowbits[bit][act] << rule[:opts][:sid]
			end
		end
	end

	def add_directory(dir)
		files = Dir.glob("#{dir}/*.rules")
		parser = RuleFileParser.new
		files.each do |file|
			process_file parser, file
		end
		#PP.pp @flowbits
	end

	def process_file(parser,file)
		rules = parser.parse_file(file)
		@rules.merge! rules
		rules.each_value do |rule|
			index_flowbits(rule)
		end
	end

	def disable_file(name)
		@rules.each_value do |rule|
			rule[:meta][:enabled] = false if rule[:meta][:file] == name
		end
	end

	def disable_sid(sid)
		# @TODO
		@rules[sid][:meta][:enabled] = false if @rules[sid]
	end

	def resolve_flowbits(rule)
		return unless rule[:meta][:enabled]
		return unless rule[:opts][:flowbits]
		acts = ['isset','isnotset']
		acts.each do |act|
			next unless rule[:opts][:flowbits][act]
			rule[:opts][:flowbits][act].each do |bit|
				enable_bitset(bit)
			end
		end
	end

	def enable_bitset(bit)
		@flowbits[bit]['set'].each do |sid|
			flowbit_enable_rule @rules[sid]
		end
		@flowbits[bit]['unset'].each do |sid|
			flowbit_enable_rule @rules[sid]
		end
	end

	def flowbit_enable_rule(rule)
		return if rule[:meta][:enabled] or rule[:opts][:flowbits]['noalert']
		#puts "enabling no alert %s" % [rule[:opts][:msg]]
		rule[:meta][:enabled] = true
		rule[:opts][:flowbits]['noalert'] = true
	end

	def write_enabled(rules_file,map_file)
		@rules.each_value do |rule|
			next unless rule[:meta][:enabled]
			resolve_flowbits(rule)
		end

		rules = File.open(rules_file,'w')
		map = File.open(map_file,'w')
		map.write("#v2\n");

		writer = RuleWriter.new
		@rules.each_value do |rule|
			next unless rule[:meta][:enabled]
			rules.write(writer.write(rule));
			rules.write("\n");
			map.write(writer.write_sid_map(rule))
			map.write("\n");
		end
		rules.close()
		map.close()
	end
end
