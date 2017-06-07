class SWFObject
	def initialize(fp)
		@time = Time.new
		@swf = fp
		@swf_workspace = Dir.pwd+"/"+@swf+"."+(@time.to_i).to_s
		@swf_report = ""
		
		@swf_dump = ""
		@swf_actionscript = Array.new()
		@swf_vuln = []  #  level | vulnerability | file | line | code data
		@swf_loaderInfo = []   # file | line | code data
		
		@swf_report_path=""
		@swf_report_template=""
		#Set Report Template
		rf = File.open(File.dirname(__FILE__)+"/rtemplate.html", "r")
			rf.each_line do | line |
				@swf_report_template = @swf_report_template+line
			end
		@swf_report_data=""
	end
	def decompileSWF # Decompile SWF File [ flash > actionscript ] 
	# ffdec -export script ./asd simpleCalendar.swf
	puts " > Making source Directory"
	Dir.mkdir(@swf_workspace+"/source")
	puts " > Decompiling.."
	system($path_ffdec+" -export script "+@swf_workspace+"/source/ "+@swf+" > /dev/null 2>&1")  ## ffdec
	puts " > Success"
	end
	
	def dumpSWF # Dump SWF
	# swfdump -D	
	puts " > Dumping.."
	system($path_swfdump+" -D "+@swf+" > "+@swf_workspace+"/source/dump")  ## ffdec
	puts " > Success"
	end
	
	# swfstrings
	
	
	def findLoaderInfo
		#ActionScript2 
		#LoaderInfo(this.root.loaderInfo).parameters;
		#ActionScript3 
		#this.loaderInfo.parameters;
		i=0
		for count in 0 ... @swf_actionscript.size
			if(@swf_actionscript[count].index("loaderInfo.parameters") != nil)
				sindex = @swf_actionscript[count].index("loaderInfo.parameters")
				@swf_loaderInfo.push([@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
		end
		puts "   - #{i} input param point found!"
	end
	def findVulnFunction
		#loadVariables()
		#loadMovie()
		#getURL()
		#loadMovieNum()
		#FScrollPane.loadScrollContent()
		#LoadVars.load 
		#LoadVars.send 
		#XML.load ( 'url' )
		#LoadVars.load ( 'url' ) 
		#Sound.loadSound( 'url' , isStreaming ); 
		#NetStream.play( 'url' );
		i = 0
		for count in 0 ... @swf_actionscript.size
			if(@swf_actionscript[count].index("loadVariables(") != nil)
				sindex = @swf_actionscript[count].index("loadVariables(")
				@swf_vuln.push([2,"vuln func - loadVariables()",@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("loadMovie(") != nil)
				sindex = @swf_actionscript[count].index("loadMovie(")
				@swf_vuln.push([2,"vuln func - loadMovie()",@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("getURL(") != nil)
				sindex = @swf_actionscript[count].index("getURL(")
				@swf_vuln.push([2,"vuln func - getURL()",@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("loadMovieNum(") != nil)
				sindex = @swf_actionscript[count].index("loadMovieNum(")
				@swf_vuln.push([2,"vuln func - loadMovieNum()",@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("FScrollPane.loadScrollContent(") != nil)
				sindex = @swf_actionscript[count].index("FScrollPane.loadScrollContent(")
				@swf_vuln.push([2,"vuln func - FScrollPane.loadScrollContent()",@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("LoadVars.load(") != nil)
				sindex = @swf_actionscript[count].index("LoadVars.load(")
				@swf_vuln.push([2,"vuln func - LoadVars.load()",@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("LoadVars.send(") != nil)
				sindex = @swf_actionscript[count].index("LoadVars.send(")
				@swf_vuln.push([2,"vuln func - LoadVars.send()",@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("XML.load(") != nil)
				sindex = @swf_actionscript[count].index("XML.load(")
				@swf_vuln.push([2,"vuln func - XML.load()",@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("Sound.loadSound(") != nil)
				sindex = @swf_actionscript[count].index("Sound.loadSound(")
				@swf_vuln.push([2,"vuln func - Sound.loadSound()",@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("NetStream.play(") != nil)
				sindex = @swf_actionscript[count].index("NetStream.play(")
				@swf_vuln.push([2,"vuln func - NetStream.play()",@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
		end
		puts "   - #{i} vulnerable function point found!"
	end
	def findExternalInterface
		i=0
		for count in 0 ... @swf_actionscript.size
			if(@swf_actionscript[count].index("ExternalInterface.call(") != nil)
				sindex = @swf_actionscript[count].index("ExternalInterface.call(")
				@swf_vuln.push([3,"use ExternalInterface.call()",@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
		end
		puts "   - #{i} ExternalInterface.call() found!"
	end
	
	def vanalysis
		# @swf_workspace+"/source/script/" is actionscript directory
		# @swf_workspace+"/source/dump" is dump result
		fdump = File.open(@swf_workspace+"/source/dump","r")
		fdump.each_line do | line |
			@swf_dump =  @swf_dump+line
		end
		puts " > Loaded dump file"
		@aslist = Dir[@swf_workspace+'**/**/*.as']
		for index in 0 ... @aslist.size
			#puts "@aslist[#{index}] = #{@aslist[index].inspect}"
			fasTemp = ""
			fas = File.open(@aslist[index], "r")
				fas.each_line do | line |
					fasTemp = fasTemp+line
				end		
			@swf_actionscript.push(fasTemp)
		end
		puts " > Loaded all actionscript [#{@aslist.size}] files"
		findLoaderInfo()
		findVulnFunction()
		findExternalInterface
	end
	
	def genReport # Generate Report file
		@swf_report_path = "./report_"+@swf+"."+(@time.to_i).to_s+".html"
		tempData = @swf_report_template
		puts " > Loaded report template"
		
		
		### Security Logic Area!!!
		
		
		######################
		puts " > Generating.."
		# Set r_info
		r_info = "<font size=5>Application Name: </font><font size=5 color=green>[ #{@swf} ]</font><br><br><font size=4>#loaderInfo</font><table><tr><td>AS File</td><td align=center>Line</td><td>Code</td></tr>"
		for temp in @swf_loaderInfo
			r_info = r_info+"<tr><td>#{temp[0]}</td><td>#{temp[1]}</td><td><pre><code>#{temp[2]}</code></pre></td></tr>"
		end
		r_info = r_info+"</table>"
		
		# Set r_vuln
		r_vuln = "<table><tr><td align=center>Level</td><td>Vulnerability</td><td>AS File</td><td align=center>Line</td><td>Code</td></tr>"
		for temp in @swf_vuln
			r_vuln = r_vuln+"<tr><td>#{temp[0]}</td><td>#{temp[1]}</td><td>#{temp[2]}</td><td>#{temp[3]}</td><td><pre><code>#{temp[4]}</code></pre></td></tr>"
		end
		r_vuln = r_vuln+"</table>"
		
		r_dump = "<pre>"+@swf_dump="</pre>"
		r_istr=""
		r_html=""
		
		tempData = tempData.gsub("{#!info}",r_info)
		tempData = tempData.gsub("{#!vuln}",r_vuln)
		tempData = tempData.gsub("{#!dump}",r_dump)
		tempData = tempData.gsub("{#!istr}",r_istr)
		tempData = tempData.gsub("{#!html}",r_html)
		
		rFile = File.new(@swf_report_path, 'w')
		if rFile
			puts rFile.syswrite(tempData)
			puts " > Report Writing.."
		else
			puts " > Report Error.."
		end
	end
	
	def scan()
		puts "Start VAIS.. Scanning to "+@swf+" file."
		puts "[INF] Making Workspace ["+@swf_workspace+"]" 
		Dir.mkdir(@swf_workspace)
		puts "[INF] Decompile SWF >> Actionscript" 
		decompileSWF()
		puts "[INF] Dump SWF File.." 
		dumpSWF()
		puts "[INF] Vulnerability Analysis.." 
		vanalysis()
		puts "[INF] Generate Report.." 
		genReport()
		puts "Scan Finish. open this file ["+@swf_report+"]"
		
	end
end
