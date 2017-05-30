class SWFObject
	def initialize(fp)
		@file_path = fp
		@time = "TIME"
	end
	def scan()
		puts "SCAN"+@file_path
	end
end
