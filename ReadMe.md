GTGPB By Silentwarior112: A Gran Turismo .gpb extractor and maker

Features:
1. Extract the .gpb asset packages that contain various UI / menu textures, and output a functional configuration file to generate them back into a .gpb.
	GTGPB will dump the contents of the gpb, decompress any applicable files with PolyphonyPS2Zip, and convert any textures into PNG format with GTPS2ModelTool automatically.
	This allows for an easy workflow free of any manual file conversions, GTGPB now handles it all with version 1.1.

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
	- Any Microsoft dotnet frameworks that PolyphonyPS2Zip and GTPS2ModelTool require to run. (5.0 and 8.0)

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

gpb2 for PS3 is 99.9% identical to gpb2 for PS2, the only difference is the padding is written
to the next factor of 128 instead of 16. However, I have tested factor of 16 padding on GT HD's
race_display\ps3\US\display.gpb and it works fine, so gpb2 generation with this tool 
is the same for both the PS2 and PS3 version.

gpb3's padding structure is not 100% replicated when generating a gpb3 with this tool.
It is similar but slightly different than original files.
Testing is needed to verify that the padding structure generated
with this tool is OK.

Tested gpb Extractions:
Gran Turismo 4 Prologue NTSC-J: projects\prologue\JP\SchoolRoot.gpb

Gran Turismo 4 Prologue PAL: projects\prologue\BR\SchoolRoot.gpb

Gran Turismo 4: projects\arcade\US\alfaromeo.gpb
		race_display\gt4\US\display.gpb

Gran Turismo HD: race_display\ps3\US\display.gpb

Gran Turismo PSP: projects\gt5m\race\US\QuickArcadeRoot.gpb

Gran Turismo 6: projects\gt6\race\US\OnboardMeterRoot.gpb

Fully Tested gpb Generations:
Gran Turismo 4: projects\arcade\US\alfaromeo.gpb
		projects\arcade\US\mercedes.gpb
		race_display\gt4\US\display.gpb

Gran Turismo HD: race_display\ps3\US\display.gpb

Binary data structures:

-- 1st iteration of gpb: gpb0--

"gpb0" // header

02 00 00 00 // texture count

18 00 00 00 // label offset
50 00 00 00 // texture offset

2F 00 00 00 // label offset
B0 01 00 00 // texture offset

// Zero-terminated strings
image/option/check.png 00
image/option/dot.png 00
Insert 5E / "^" until the next factor of 16

*Texture data*
Insert 5E / "^" until the next factor of 16

*Texture data*
Insert 5E / "^" until the next factor of 16

*Texture data*
Insert 5E / "^" until the next factor of 16

Repeat until end

-- 2nd iteration of gpb: gpb1--

"gpb1" // header

00 00 00 00 00 00 00 00 // 8 BYTES OF PADDING FOR NO REASON AT ALL, WTF WAS THE POINT OF THIS PD AHHHH

0A 00 00 00 // texture count

60 00 00 00 // label offset
80 01 00 00 // texture offset

77 00 00 00 // label offset
E0 02 00 00 // texture offset

94 00 00 00 // label offset
80 05 00 00 // texture offset

AD 00 00 00 // label offset
20 09 00 00 // texture offset

CC 00 00 00 // label offset
E0 0D 00 00 // texture offset

E7 00 00 00 // label offset
C0 17 00 00 // texture offset

FE 00 00 00 // label offset
80 21 00 00 // texture offset

1E 01 00 00 // label offset
B0 25 00 00 // texture offset

38 01 00 00 // label offset
B0 27 00 00 // texture offset

58 01 00 00 // label offset
00 2C 00 00 // texture offset

// Zero-terminated strings
image/car/car_ring.png 00
image/car/car_ring_flare.png 00
image/car/color_ring.png 00
image/car/color_ring_flare.png 00
image/car/colorball_GT.png 00
image/car/colortip.png 00
image/car/colortip_specular.png 00
image/crs/course_ring.png 00
image/crs/course_ring_flare.png 00
image/crs/mini_tsukuba.png 00
Insert 5E / "^" until the next factor of 16

*Texture data*
Insert 5E / "^" until the next factor of 16

*Texture data*
Insert 5E / "^" until the next factor of 16

*Texture data*
Insert 5E / "^" until the next factor of 16

Repeat until end

--3rd iteration of gpb: gpb2--

67 70 62 32  // "gpb2"

00 00 00 00 00 00 00 00 // Same as gpb1, 8 bytes of zeroes for no reason

06 00 00 00 // Number of textures in the container

// Texture #1 metadata
70 00 00 00 // label offset
30 01 00 00 // texture offset
A0 01 00 00 00 00 00 00  // Byte count of the texture data, however the game doesn't care about this whatsoever so these can just be all zeroes

// Texture #2 metadata
93 00 00 00 // label offset
D0 02 00 00 // texture offset
A0 01 00 00 00 00 00 00  // Byte count of the texture data, however the game doesn't care about this whatsoever so these can just be all zeroes

// Texture #3 metadata
B5 00 00 00 // label offset
70 04 00 00 // texture offset
70 16 00 00 00 00 00 00  // Byte count of the texture data, however the game doesn't care about this whatsoever so these can just be all zeroes

// Texture #4 metadata
D3 00 00 00 // label offset
E0 1A 00 00 // texture offset
70 7B 01 00 00 00 00 00  // Byte count of the texture data, however the game doesn't care about this whatsoever so these can just be all zeroes

// Texture #5 metadata
EE 00 00 00 // label offset
50 96 01 00 // texture offset
70 7B 01 00 00 00 00 00  // Byte count of the texture data, however the game doesn't care about this whatsoever so these can just be all zeroes

// Texture #6 metadata
0C 01 00 00 // label offset
C0 11 03 00 // texture offset
90 CF 00 00 00 00 00 00  // Byte count of the texture data, however the game doesn't care about this whatsoever so these can just be all zeroes

// Zero-terminated strings
image/arcade/common/arrow_down.png 00
image/arcade/common/arrow_top.png 00
image/arcade/top/GT4_logo.png 00
image/arcade/top/JP/gt.png 00
image/arcade/top/JP/gt4ol.png 00
image/arcade/top/JP/maker_gt.png 00
Insert 5E / "^" until the next factor of 16, For PS3 it pads to next factor of 128

*Texture data*
Insert 5E / "^" until the next factor of 16

*Texture data*
Insert 5E / "^" until the next factor of 16

*Texture data*
Insert 5E / "^" until the next factor of 16

Repeat until end

-- 4th iteration of gpb: gpb3 --
As I mentioned above, the padding structure of gpb3 files
is not 100% replicated / figured.
The padding structure mentioned here is what is currently
implemented into the gpb3 generation of this tool.

(This is Big-endian instead of little-endian)

"3bpg" // haha PD forgot that PS3 is Big-endian

00 00 00 00 // padding, static

00 00 00 20 // 20, byte count of the header, static

00 00 00 04 // Texture count, dynamic

00 00 00 20 // 20, start of the metadata chunk, static

00 00 00 60 // 60, start of the string chunk, dynamic

00 00 01 00 // 100, start of the texture data, dynamic

00 00 00 00 // padding, static

00 00 00 60 // filename offset for #1
00 00 01 00 // texture offset for #1
00 00 04 13 00 00 00 00 // byte count and 4 bytes of padding, unsure if PS3-era gt games use this at all

00 00 00 86 // filename offset for #2
00 00 05 80 // texture offset for #2
00 00 03 33 00 00 00 00 // byte count and 4 bytes of padding

00 00 00 AF // filename offset for #3
00 00 09 00 // texture offset for #3
00 00 0B A3 00 00 00 00 // byte count and 4 bytes of padding

00 00 00 D4 // filename offset for #4
00 00 15 00 // texture offset for #4
00 00 0F 13 00 00 00 00 // byte count and 4 bytes of padding

image/component/ps3/arrow_balloon.dds 00
image/component/ps3/arrow_balloon_up.dds 00
image/component/ps3/base_balloon.dds 00
image/gt5/icon/icon_close.dds 00
5E padding // Pad to 0x00000100, or if already above that, pad to next factor of 64

*Texture data*
5E padding // pad until next factor of 64 in decimal / 80 in hex

*Texture data*
5E padding // pad until next factor of 64 in decimal / 80 in hex

*Texture data*
5E padding // pad until next factor of 64 in decimal / 80 in hex

Repeat until end

