# Fork Changes

This fork supports YARA v4.2.1 (the original supposed v3). This changed how UNDEFINED was returned and this fork updated the returns to use YR_UNDEFINED rather than just UNDEFINED.

The use of strstr() was also changed to memmem() to support searching through files with null bytes inside (such as VBA binary files). This may or may not be compatible with all systems.

# yara_zip_module
This yara module can be used to search for strings inside a zip (.docx word file format) file. The files inside a zip are compressed and therefore not very well searchable for strings. This yara module unzips a requested file in memory and searches for a given string.

## Installation
The installation of the module should be pretty simple, but yara has to be built from source..
1. Clone the yara repository (https://github.com/VirusTotal/yara)
2. Copy yara_zip_modules files into the libyara folder of the yara clone:

	yara_zip_module/miniz.c --> yara/libyara/miniz.c
	
	yara_zip_module/include/yara/miniz.h --> yara/libyara/include/yara/miniz.h

	yara_zip_module/modules/zip.c --> yara/libyara/modules/zip.c

3. Edit the file yara/libyara/Makefile.am to add the new module/sources:

	MODULES += modules/zip.c

	Add to yarainclude_HEADERS: include/yara/miniz.h
	
	Add to libyara_la_SOURCES: miniz.c
	
4. Add the module to the module_list file in the modules folder:
	
	MODULE(zip)
	
5. Now you can build yara by executing the make command inside the root folder.

More information can be found here: https://yara.readthedocs.io/en/v4.2.1/writingmodules.html

## Usage

The yara zip module has at the moment only one function `has_string(<file_inside_zip>, <search_string>)`
Following an example of a yara rule using the `has_string(..)` function.
If the given string was found, then the return value of the `has_string` function equals the offset inside the requested file.

	import "zip"

	rule embedded_html
	{
	    meta:
	    author = "@stoerchl"
	    info = "searches for a given string inside a zip file"
      
	    condition:
	        zip.has_string("word/document.xml", "wp15:webVideoPr") > 0
	}


## Thanks to
This module would not be working without this data compression library:

https://github.com/richgel999/miniz/

And without the yara project there obviously would have been no new yara module ;-)

https://github.com/VirusTotal/yara

