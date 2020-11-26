# jamulus-wireshark
Wireshark dissector for the Jamulus protocol, written in LUA

* Displays protocol messages and their contents. _A current limitation is that long messages split using the Jamulus split message protocol are not reassembled into the original long message._

* Displays audio packets indicating the quality, stereo/mono and sequence numbers if included (Jamulus 3.6.0+).
  - Quality is shown as "Low", "Medium", "High" or "Higher". "High" corresponds to the high setting for clients up to 3.6.0, and "Higher" corresponds to the high setting for clients 3.6.1 onwards.

## Installation

The file `jamulus.lua` should be copied to an appropriate `plugins` directory for Wireshark.

To find the appropriate directories for personal or global Lua plugins, display the **About Wireshark** window and select **Folders**

### Under Windows

For the current user only, copy to `%USERPROFILE%\AppData\Roaming\Wireshark\plugins\`

For all users on the system, copy to `c:\Program Files\Wireshark\plugins\`

### Under MacOS

For the current user only, copy to `~/.local/lib/wireshark/plugins/`

For all users on the system, copy to `/Applications/Wireshark.app/Contents/PlugIns/wireshark/`. _Note that after installing a new version of Wireshark, it should be opened and verified by the OS before copying any plugins to the system directory. Otherwise the verification will fail. Once the verification has been done, it is safe to copy plugins to the above directory._

### Under Linux on Raspberry Pi OS

For the current user only, copy to `~/.local/lib/wireshark/plugins/`

For all users on the system, copy to `/usr/lib/arm-linux-gnueabihf/wireshark/plugins/`

### Under other Linux

For the current user only, copy to `~/.local/lib/wireshark/plugins/`

For all users on the system, copy to the Wireshark plugins directory, which will probably be either `/usr/lib/wireshark/plugins/` or `/usr/lib/*/wireshark/plugins/`

