GTGPB By Silentwarior112: A Gran Turismo .gpb extractor and maker

Features:
1. Extract the .gpb asset packages that contain various UI / menu textures, and output a functional configuration file to generate them back into a .gpb.
	GTGPB will dump the contents of the gpb, decompress any applicable files with PolyphonyPS2Zip, and convert any textures into PNG format with GTPS2ModelTool or TXS3 Converter automatically.
	This allows for an easy workflow free of any manual file conversions, GTGPB now handles it all with version 1.2.

	Typical formats seen in a .gpb: Tex1 as .img (PS2-era GT games), TXS3 as .img (PS3-era GT games), etc.

2. Generate a .gpb with loose .img files using a configuration file.
	The configuration file will contain the path to your file(s), and their label that gets injected into the .gpb's header data.
	The texture labels are REQUIRED to be exactly what the game's scripting logic is looking for, and the textures themselves
	must be in the correct order as well. If not, the game will not display it, so make sure the configuration file is set correctly.

3. Update the file locations in an existing .gpb.
	If you add or remove files from the asset folder, or move the folder to another location on your
	computer, you will need to update the .ini configuration file in order to generate gpb files again.

	Simply run the "Update GPB file entries" to fix the configuration file.
	With version 1.1, the strict ASCII lexicographic file order is now handled correctly.
	Currently it will set the compression flag to true for ALL files in the directory.

How to use:
1. If you do not have python installed on your computer, you will need to install it first (~26mb download).
	https://www.python.org/downloads/

2. Download the required external tools:
	- [GTPS2ModelTool 1.1.0 or newer](https://github.com/Nenkai/GTPS2ModelTool/releases)
	- [PolyphonyPS2Zip](https://github.com/pez2k/gt2tools/releases/tag/PolyphonyPS2Zip01)
	- Version 1.2.0 uses [This fork of TXS3Converter](https://github.com/Silentwarior112/TXS3Converter/releases/tag/1.3.1)
	- The Microsoft dotnet frameworks that PolyphonyPS2Zip, GTPS2ModelTool, and TXS3 Converter require to run. (5.0, 8.0, 9.0)

3. Place the tools in the corresponding folders to complete the installation.

4. Simply double-click the GTGPB.py file, and the GUI and console will load.

Extracting a .gpb:
	Click the extract button, locate your .gpb, then specify the output folder
	where the extracted textures will go.

	The original file/folder structure defined in the texture labels is replicated,
	and a configuration file to generate the textures back into a .gpb is generated
	in the same root folder you selected.

	All versions of gpb files are supported through this one button.

	Version 1.1 has not updated the handling of gpb3 files.


Modifying the asset folder:
	Replace the original file(s) with your own. Since textures are automatically converted,
	you can edit the .png files directly and immediately generate a new .gpb to test.
	When adding new files, update the GPB file entries then generate the new .gpb file.

	For most situations, adhoc scripting is not modified, so you should only
	extract the .gpb, overwrite the dumped files with your own, and generate the .gpb.

	If you are modifying adhoc script and decide to change what labels it looks for,
	be mindful not to give texture labels any illegal characters if you want the script
	to still be able to extract and pack these correctly.

	To avoid any issues, stick to uppercase and lowercase letters,
	the forward slash ( / ),
	period ( . ),
	underscore ( _ ),
	and nothing else, and always label your textures as a file.
	For example, the simplest a label should be is "folder/file.extension"

	This will prevent any possible errors with the
	string and path handling in the tool's code.

Updating a configuration file:
	Click the "Update GPB file entries" button to generate a new configuration file,
	it will be saved as "generated_config.ini".
	With version 1.1, the strict ASCII lexicographic file order is now handled correctly.
	Currently it will set the compression flag to true for ALL files in the directory.

Generating a .gpb:
	Click the generate button corresponding to your desired target gpb version.
	When a gpb is extracted, the configuration file is named based on what gpb version was extracted
	so this will tell you which version you need to generate. However, there is no restriction
	on which version you can generate, if for whatever reason you want to build a gpb0 from an asset package dumped
	from a gpb3, you can do so.
	
	Specify your configuration file,
	then specify the .gpb output file.

	It will pack the textures specified within the configuration file.


Supported gpb formats:
gpb0: GT4 Prologue NTSC-J (PBPX-95523)
gpb1: GT4 Prologue PAL (SCES-52438), GT4 First Preview (NTSC-J) (PCPX-96649)
gpb2 (PS2): All retail releases of GT4, GT4 MX-5 Demo, Tourist Trophy
gpb2 (PS3): GT HD, GT5 prologue
gpb3: GTPSP, GT5, GT6
