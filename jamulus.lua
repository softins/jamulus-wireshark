-------------------------------------------------------------------------------
--
-- author: Tony Mountifield <tony@mountifield.org>
-- Copyright (c) 2020, Tony Mountifield
-- This code is in the Public Domain, or the BSD (3 clause) license
-- if Public Domain does not apply in your country.
--
-- Version: 1.0
--
-------------------------------------------------------------------------------
--[[

    This code is a plugin for Wireshark, to dissect Jamulus protocol messages
    over UDP.

]]----------------------------------------


----------------------------------------
-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

----------------------------------------
-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- set it to debug_level.DISABLED to disable debug printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1

-- a table of our default settings - these can be changed by changing
-- the preferences through the GUI or command-line; the Lua-side of that
-- preference handling is at the end of this script file
local default_settings =
{
    debug_level  = DEBUG,
    enabled      = true, -- whether this dissector is enabled or not
    port1        = 22120, -- first UDP port number for Jamulus
    port2        = 22139, -- last UDP port number for Jamulus
}


local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            info(table.concat({"Lua: ", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    else
        dprint = function() end
        dprint2 = dprint
    end
end
-- call it now
resetDebugLevel()

----------------------------------------
-- a function to convert tables of enumerated types to value-string tables
-- i.e., from { "name" = number } to { number = "name" }
local function makeValString(enumTable)
    local t = {}
    for name,num in pairs(enumTable) do
        t[num] = name
    end
    return t
end

--------------------------------------------------------------------------------
-- creates a Proto object, but doesn't register it yet
jamulus = Proto("Jamulus", "Jamulus Protocol")

opcodes = {
	ILLEGAL				= 0,	-- illegal ID
	ACKN				= 1,	-- acknowledge
	JITT_BUF_SIZE			= 10,	-- jitter buffer size
	REQ_JITT_BUF_SIZE		= 11,	-- request jitter buffer size
	NET_BLSI_FACTOR			= 12,	-- OLD (not used anymore)
	CHANNEL_GAIN			= 13,	-- set channel gain for mix
	CONN_CLIENTS_LIST_NAME		= 14,	-- OLD (not used anymore)
	SERVER_FULL			= 15,	-- OLD (not used anymore)
	REQ_CONN_CLIENTS_LIST		= 16,	-- request connected client list
	CHANNEL_NAME			= 17,	-- OLD (not used anymore)
	CHAT_TEXT			= 18,	-- contains a chat text
	PING_MS				= 19,	-- OLD (not used anymore)
	NETW_TRANSPORT_PROPS		= 20,	-- properties for network transport
	REQ_NETW_TRANSPORT_PROPS	= 21,	-- request properties for network transport
	DISCONNECTION			= 22,	-- OLD (not used anymore)
	REQ_CHANNEL_INFOS		= 23,	-- request channel infos for fader tag
	CONN_CLIENTS_LIST		= 24,	-- channel infos for connected clients
	CHANNEL_INFOS			= 25,	-- set channel infos
	OPUS_SUPPORTED			= 26,	-- tells that OPUS codec is supported
	LICENCE_REQUIRED		= 27,	-- licence required
	REQ_CHANNEL_LEVEL_LIST		= 28,	-- request the channel level list
	VERSION_AND_OS			= 29,	-- version number and operating system
	CHANNEL_PAN			= 30,	-- set channel pan for mix
	MUTE_STATE_CHANGED		= 31,	-- mute state of your signal at another client has changed
	CLIENT_ID			= 32,	-- current user ID and server status
	CLM_PING_MS			= 1001,	-- for measuring ping time
	CLM_PING_MS_WITHNUMCLIENTS	= 1002,	-- for ping time and num. of clients info
	CLM_SERVER_FULL			= 1003,	-- server full message
	CLM_REGISTER_SERVER		= 1004,	-- register server
	CLM_UNREGISTER_SERVER		= 1005,	-- unregister server
	CLM_SERVER_LIST			= 1006,	-- server list
	CLM_REQ_SERVER_LIST		= 1007,	-- request server list
	CLM_SEND_EMPTY_MESSAGE		= 1008,	-- an empty message shall be send
	CLM_EMPTY_MESSAGE		= 1009,	-- empty message
	CLM_DISCONNECTION		= 1010,	-- disconnection
	CLM_VERSION_AND_OS		= 1011,	-- version number and operating system
	CLM_REQ_VERSION_AND_OS		= 1012,	-- request version number and operating system
	CLM_CONN_CLIENTS_LIST		= 1013,	-- channel infos for connected clients
	CLM_REQ_CONN_CLIENTS_LIST	= 1014,	-- request the connected clients list
	CLM_CHANNEL_LEVEL_LIST		= 1015,	-- channel level list
	CLM_REGISTER_SERVER_RESP	= 1016,	-- status of server registration request
}
local opcodes_valstr = makeValString(opcodes)

local countries = {
	AnyCountry				= 0,
	Afghanistan				= 1,
	Albania					= 2,
	Algeria					= 3,
	AmericanSamoa				= 4,
	Andorra					= 5,
	Angola					= 6,
	Anguilla				= 7,
	Antarctica				= 8,
	AntiguaAndBarbuda			= 9,
	Argentina				= 10,
	Armenia					= 11,
	Aruba					= 12,
	Australia				= 13,
	Austria					= 14,
	Azerbaijan				= 15,
	Bahamas					= 16,
	Bahrain					= 17,
	Bangladesh				= 18,
	Barbados				= 19,
	Belarus					= 20,
	Belgium					= 21,
	Belize					= 22,
	Benin					= 23,
	Bermuda					= 24,
	Bhutan					= 25,
	Bolivia					= 26,
	BosniaAndHerzegowina			= 27,
	Botswana				= 28,
	BouvetIsland				= 29,
	Brazil					= 30,
	BritishIndianOceanTerritory		= 31,
	Brunei					= 32,
	Bulgaria				= 33,
	BurkinaFaso				= 34,
	Burundi					= 35,
	Cambodia				= 36,
	Cameroon				= 37,
	Canada					= 38,
	CapeVerde				= 39,
	CaymanIslands				= 40,
	CentralAfricanRepublic			= 41,
	Chad					= 42,
	Chile					= 43,
	China					= 44,
	ChristmasIsland				= 45,
	CocosIslands				= 46,
	Colombia				= 47,
	Comoros					= 48,
	CongoKinshasa				= 49,
	CongoBrazzaville			= 50,
	CookIslands				= 51,
	CostaRica				= 52,
	IvoryCoast				= 53,
	Croatia					= 54,
	Cuba					= 55,
	Cyprus					= 56,
	CzechRepublic				= 57,
	Denmark					= 58,
	Djibouti				= 59,
	Dominica				= 60,
	DominicanRepublic			= 61,
	EastTimor				= 62,
	Ecuador					= 63,
	Egypt					= 64,
	ElSalvador				= 65,
	EquatorialGuinea			= 66,
	Eritrea					= 67,
	Estonia					= 68,
	Ethiopia				= 69,
	FalklandIslands				= 70,
	FaroeIslands				= 71,
	Fiji					= 72,
	Finland					= 73,
	France					= 74,
	Guernsey				= 75,
	FrenchGuiana				= 76,
	FrenchPolynesia				= 77,
	FrenchSouthernTerritories		= 78,
	Gabon					= 79,
	Gambia					= 80,
	Georgia					= 81,
	Germany					= 82,
	Ghana					= 83,
	Gibraltar				= 84,
	Greece					= 85,
	Greenland				= 86,
	Grenada					= 87,
	Guadeloupe				= 88,
	Guam					= 89,
	Guatemala				= 90,
	Guinea					= 91,
	GuineaBissau				= 92,
	Guyana					= 93,
	Haiti					= 94,
	HeardAndMcDonaldIslands			= 95,
	Honduras				= 96,
	HongKong				= 97,
	Hungary					= 98,
	Iceland					= 99,
	India					= 100,
	Indonesia				= 101,
	Iran					= 102,
	Iraq					= 103,
	Ireland					= 104,
	Israel					= 105,
	Italy					= 106,
	Jamaica					= 107,
	Japan					= 108,
	Jordan					= 109,
	Kazakhstan				= 110,
	Kenya					= 111,
	Kiribati				= 112,
	NorthKorea				= 113,
	SouthKorea				= 114,
	Kuwait					= 115,
	Kyrgyzstan				= 116,
	Laos					= 117,
	Latvia					= 118,
	Lebanon					= 119,
	Lesotho					= 120,
	Liberia					= 121,
	Libya					= 122,
	Liechtenstein				= 123,
	Lithuania				= 124,
	Luxembourg				= 125,
	Macau					= 126,
	Macedonia				= 127,
	Madagascar				= 128,
	Malawi					= 129,
	Malaysia				= 130,
	Maldives				= 131,
	Mali					= 132,
	Malta					= 133,
	MarshallIslands				= 134,
	Martinique				= 135,
	Mauritania				= 136,
	Mauritius				= 137,
	Mayotte					= 138,
	Mexico					= 139,
	Micronesia				= 140,
	Moldova					= 141,
	Monaco					= 142,
	Mongolia				= 143,
	Montserrat				= 144,
	Morocco					= 145,
	Mozambique				= 146,
	Myanmar					= 147,
	Namibia					= 148,
	NauruCountry				= 149,
	Nepal					= 150,
	Netherlands				= 151,
	CuraSao					= 152,
	NewCaledonia				= 153,
	NewZealand				= 154,
	Nicaragua				= 155,
	Niger					= 156,
	Nigeria					= 157,
	Niue					= 158,
	NorfolkIsland				= 159,
	NorthernMarianaIslands			= 160,
	Norway					= 161,
	Oman					= 162,
	Pakistan				= 163,
	Palau					= 164,
	PalestinianTerritories			= 165,
	Panama					= 166,
	PapuaNewGuinea				= 167,
	Paraguay				= 168,
	Peru					= 169,
	Philippines				= 170,
	Pitcairn				= 171,
	Poland					= 172,
	Portugal				= 173,
	PuertoRico				= 174,
	Qatar					= 175,
	Reunion					= 176,
	Romania					= 177,
	Russia					= 178,
	Rwanda					= 179,
	SaintKittsAndNevis			= 180,
	SaintLucia				= 181,
	SaintVincentAndTheGrenadines		= 182,
	Samoa					= 183,
	SanMarino				= 184,
	SaoTomeAndPrincipe			= 185,
	SaudiArabia				= 186,
	Senegal					= 187,
	Seychelles				= 188,
	SierraLeone				= 189,
	Singapore				= 190,
	Slovakia				= 191,
	Slovenia				= 192,
	SolomonIslands				= 193,
	Somalia					= 194,
	SouthAfrica				= 195,
	SouthGeorgiaAndTheSouthSandwichIslands	= 196,
	Spain					= 197,
	SriLanka				= 198,
	SaintHelena				= 199,
	SaintPierreAndMiquelon			= 200,
	Sudan					= 201,
	Suriname				= 202,
	SvalbardAndJanMayenIslands		= 203,
	Swaziland				= 204,
	Sweden					= 205,
	Switzerland				= 206,
	Syria					= 207,
	Taiwan					= 208,
	Tajikistan				= 209,
	Tanzania				= 210,
	Thailand				= 211,
	Togo					= 212,
	TokelauCountry				= 213,
	Tonga					= 214,
	TrinidadAndTobago			= 215,
	Tunisia					= 216,
	Turkey					= 217,
	Turkmenistan				= 218,
	TurksAndCaicosIslands			= 219,
	TuvaluCountry				= 220,
	Uganda					= 221,
	Ukraine					= 222,
	UnitedArabEmirates			= 223,
	UnitedKingdom				= 224,
	UnitedStates				= 225,
	UnitedStatesMinorOutlyingIslands	= 226,
	Uruguay					= 227,
	Uzbekistan				= 228,
	Vanuatu					= 229,
	VaticanCityState			= 230,
	Venezuela				= 231,
	Vietnam					= 232,
	BritishVirginIslands			= 233,
	UnitedStatesVirginIslands		= 234,
	WallisAndFutunaIslands			= 235,
	WesternSahara				= 236,
	Yemen					= 237,
	CanaryIslands				= 238,
	Zambia					= 239,
	Zimbabwe				= 240,
	ClippertonIsland			= 241,
	Montenegro				= 242,
	Serbia					= 243,
	SaintBarthelemy				= 244,
	SaintMartin				= 245,
	LatinAmerica				= 246,
	AscensionIsland				= 247,
	AlandIslands				= 248,
	DiegoGarcia				= 249,
	CeutaAndMelilla				= 250,
	IsleOfMan				= 251,
	Jersey					= 252,
	TristanDaCunha				= 253,
	SouthSudan				= 254,
	Bonaire					= 255,
	SintMaarten				= 256,
	Kosovo					= 257,
	EuropeanUnion				= 258,
	OutlyingOceania				= 259,
	World					= 260,
	Europe					= 261,
}
local countries_valstr = makeValString(countries)

local instruments = {
	None		= 0,
	Drum_Set	= 1,
	Djembe		= 2,
	Electric_Guitar	= 3,
	Acoustic_Guitar	= 4,
	Bass_Guitar	= 5,
	Keyboard	= 6,
	Synthesizer	= 7,
	Grand_Piano	= 8,
	Accordion	= 9,
	Vocal		= 10,
	Microphone	= 11,
	Harmonica	= 12,
	Trumpet		= 13,
	Trombone	= 14,
	French_Horn	= 15,
	Tuba		= 16,
	Saxophone	= 17,
	Clarinet	= 18,
	Flute		= 19,
	Violin		= 20,
	Cello		= 21,
	Double_Bass	= 22,
	Recorder	= 23,
	Streamer	= 24,
	Listener	= 25,
	Guitar_Vocal	= 26,
	Keyboard_Vocal	= 27,
	Bodhran		= 28,
	Bassoon		= 29,
	Oboe		= 30,
	Harp		= 31,
	Viola		= 32,
	Congas		= 33,
	Bongo		= 34,
	Vocal_Bass	= 35,
	Vocal_Tenor	= 36,
	Vocal_Alto	= 37,
	Vocal_Soprano	= 38,
}
local instruments_valstr = makeValString(instruments)

local skills = {
	Not_Set		= 0,
	Beginner	= 1,
	Intermediate	= 2,
	Expert		= 3,
}
local skills_valstr = makeValString(skills)

local codecs = {
	NONE = 0,	-- none, no audio coding applied
	CELT = 1,	-- CELT
	OPUS = 2,	-- OPUS
	OPUS64 = 3,	-- OPUS64
}
local codecs_valstr = makeValString(codecs)

local opsys = {
	Windows	= 0,
	MacOS	= 1,
	Linux	= 2,
	Android	= 3,
	iOS	= 4,
	Unix	= 5,
}
local opsys_valstr = makeValString(opsys)

local status = {
	SUCCESS = 0,	-- Successfully registered
	FAILED = 1,	-- Failed to register (server list full)
}
local status_valstr = makeValString(status)

local muting = {
	Live = 0,	-- Not muted
	Muted = 1,	-- Muted
}
local muting_valstr = makeValString(muting)

----------------------------------------
-- a table of all of our Protocol's fields
local fields =
{
	tag = ProtoField.uint16("jamulus.tag", "Tag", base.DEC),
	id = ProtoField.uint16("jamulus.id", "ID", base.DEC, opcodes_valstr),
	ackid = ProtoField.uint16("jamulus.ackid", "AckID", base.DEC, opcodes_valstr),
	cnt = ProtoField.uint8("jamulus.cnt", "Cnt", base.DEC),
	chanid = ProtoField.uint8("jamulus.chanid", "Channel", base.DEC),
	country = ProtoField.uint16("jamulus.country", "Country", base.DEC, countries_valstr),
	instrument = ProtoField.uint32("jamulus.instrument", "Instrument", base.DEC, instruments_valstr),
	skill = ProtoField.uint8("jamulus.skill", "Skill", base.DEC, skills_valstr),
	gain = ProtoField.uint16("jamulus.gain", "Gain", base.DEC),
	pan = ProtoField.uint16("jamulus.pan", "Pan", base.DEC),
	mute = ProtoField.uint8("jamulus.mute", "Mute", base.DEC, muting_valstr),
	jbsize = ProtoField.uint16("jamulus.jbsize", "JBsize", base.DEC),
	len = ProtoField.uint16("jamulus.len", "Len", base.DEC),
	bns = ProtoField.uint32("jamulus.bns", "Base Netw Size", base.DEC),
	bsf = ProtoField.uint16("jamulus.bsf", "Block Size Factor", base.DEC),
	nchan = ProtoField.uint8("jamulus.nchan", "Num Chans", base.DEC),
	-- level = ProtoField.uint8("jamulus.level", "Level", base.DEC),
	levels = ProtoField.bytes("jamulus.levels", "Levels", base.SPACE),
	samrate = ProtoField.uint32("jamulus.samrate", "Sample Rate", base.DEC),
	codec = ProtoField.uint16("jamulus.codec", "Codec", base.DEC, codecs_valstr),
	cver = ProtoField.uint16("jamulus.cver", "Codec Version", base.DEC),
	carg = ProtoField.uint32("jamulus.carg", "Codec Arg", base.DEC),
	data = ProtoField.bytes("jamulus.data", "Data"),
	name = ProtoField.string("jamulus.name", "Name", base.UNICODE),
	city = ProtoField.string("jamulus.city", "City", base.UNICODE),
	chat = ProtoField.string("jamulus.chat", "Chat Text", base.UNICODE),
	crc = ProtoField.uint16("jamulus.crc", "CRC", base.HEX),
	port = ProtoField.uint16("jamulus.port", "Port", base.DEC),
	ipaddr = ProtoField.ipv4("jamulus.ipaddr", "IP Address"),
	ipaddrs = ProtoField.string("jamulus.ipaddrs", "IP Address", base.UNICODE),
	licreq = ProtoField.uint8("jamulus.licreq", "Licence Required", base.DEC),
	chanlvlopt = ProtoField.uint8("jamulus.chanlvlopt", "Chan Level Opt", base.DEC),
	txtime = ProtoField.uint32("jamulus.txtime", "Transmit Time", base.DEC),
	nclients = ProtoField.uint8("jamulus.nclients", "Num Clients", base.DEC),
	maxclients = ProtoField.uint8("jamulus.maxclients", "Max Clients", base.DEC),
	permanent = ProtoField.uint8("jamulus.permanent", "Permanent", base.DEC),
	os = ProtoField.uint8("jamulus.os", "Operating System", base.DEC, opsys_valstr),
	osver = ProtoField.string("jamulus.osver", "OS Version", base.UNICODE),
	status = ProtoField.uint8("jamulus.status", "Status", base.DEC, status_valstr),
}

-- register the ProtoFields
jamulus.fields = fields

dprint2("jamulus ProtoFields registered")


function jamulus.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	local s = "s"
	if length == 1 then s = "" end

	pinfo.cols.protocol = jamulus.name

	if buffer(0,2):le_uint() == 0 and length >= 7 then
		datalen = buffer(5,2):le_uint()

		if datalen == length - 9 then
			local subtree = tree:add(jamulus, buffer(), "Jamulus Protocol Data", "(" .. length .. " byte" .. s .. ")")
			local header = subtree:add(jamulus, buffer(0,7), "Header")

			opcode = buffer(2,2):le_uint()
			pinfo.cols.info = opcodes_valstr[opcode]
			cntr = buffer(4,1):le_uint()
			header:append_text(" (" .. opcodes_valstr[opcode] .. ", Cnt: " .. buffer(4,1):le_uint() .. ", Datalen: " .. datalen .. ")")
			header:add_le(fields.tag, buffer(0,2))
			header:add_le(fields.id,  buffer(2,2))
			header:add_le(fields.cnt, buffer(4,1))
			header:add_le(fields.len, buffer(5,2))

			disect_msg(pinfo, opcode, buffer(7,datalen), subtree)
			subtree:add_le(fields.crc, buffer(7+datalen, 2))
		else
			local subtree = tree:add(jamulus, buffer(), "Jamulus Audio Data", "(" .. length .. " byte" .. s .. ")")
			pinfo.cols.info = "Audio Data"
		end
	else
		local subtree = tree:add(jamulus, buffer(), "Jamulus Audio Data", "(" .. length .. " byte" .. s .. ")")
		pinfo.cols.info = "Audio Data"
	end
end

local function panValue(pan)
	if pan < 16384 then return math.floor((16384-pan)*100/16384+0.5) .. "% left" end
	if pan > 16384 then return math.floor((pan-16384)*100/16384+0.5) .. "% right" end
	return "Centre"
end

local function gainValue(gain)
	return math.floor(gain*100/32768+0.5) .. "%"
end

function disect_msg(pinfo, opcode, buf, subtree)
	local s = "s"
	if buf:len() == 1 then s = "" end
	local msgdata = subtree:add(jamulus, buf, "Data", "("  .. buf:len() .. " byte" .. s .. ")")
	local n

	if opcode == opcodes.ILLEGAL then
		msgdata:add(fields.data, buf)
	elseif opcode == opcodes.ACKN then
		local ackopcode = buf:le_uint()
		msgdata:add_le(fields.ackid, buf)
		pinfo.cols.info:append(" (" .. opcodes_valstr[ackopcode] .. ")")
	elseif opcode == opcodes.JITT_BUF_SIZE then
		msgdata:add_le(fields.jbsize, buf)
		pinfo.cols.info:append(" (" .. buf:le_uint() .. ")")
	elseif opcode == opcodes.REQ_JITT_BUF_SIZE then
		-- no data
	elseif opcode == opcodes.NET_BLSI_FACTOR then
		-- Obsolete
	elseif opcode == opcodes.CHANNEL_GAIN then
		local gain = gainValue(buf(1,2):le_uint())
		msgdata:add_le(fields.chanid, buf(0,1))
		msgdata:add_le(fields.gain, buf(1,2)):append_text(" (" .. gain .. ")")
		pinfo.cols.info:append(" ([" .. buf(0,1):le_uint() .. "] => " .. gain .. ")")
	elseif opcode == opcodes.CONN_CLIENTS_LIST_NAME then
		-- Obsolete
	elseif opcode == opcodes.SERVER_FULL then
		-- Obsolete
	elseif opcode == opcodes.REQ_CONN_CLIENTS_LIST then
		-- no data
	elseif opcode == opcodes.CHANNEL_NAME then
		-- Obsolete
	elseif opcode == opcodes.CHAT_TEXT then
		n = buf(0,2):le_uint()
		if n > 0 then
			msgdata:add(fields.chat, buf(2,n))
			pinfo.cols.info:append(" (\"" .. buf(2,n):string() .. "\")")
		end
	elseif opcode == opcodes.PING_MS then
		-- Obsolete
	elseif opcode == opcodes.NETW_TRANSPORT_PROPS then
		msgdata:add_le(fields.bns, buf(0,4))
		msgdata:add_le(fields.bsf, buf(4,2))
		msgdata:add_le(fields.nchan, buf(6,1))
		msgdata:add_le(fields.samrate, buf(7,4))
		msgdata:add_le(fields.codec, buf(11,2))
		msgdata:add_le(fields.cver, buf(13,2))
		msgdata:add_le(fields.carg, buf(15,4))
		pinfo.cols.info:append(
			" (BNS=" .. buf(0,4):le_uint()
			.. ", BSF=" .. buf(4,2):le_uint()
			.. ", Chans=" .. buf(6,1):le_uint()
			.. ", SRate=" .. buf(7,4):le_uint()
			.. ", Codec=" .. codecs_valstr[buf(11,2):le_uint()]
			.. ", Ver=" .. buf(13,2):le_uint()
			.. ", Arg=" .. buf(15,4):le_uint()
			.. ")"
		)
	elseif opcode == opcodes.REQ_NETW_TRANSPORT_PROPS then
		-- no data
	elseif opcode == opcodes.DISCONNECTION then
		-- Obsolete
	elseif opcode == opcodes.REQ_CHANNEL_INFOS then
		-- no data
	elseif opcode == opcodes.CONN_CLIENTS_LIST then
		local c = 0
		local i = 0
		while i < buf:len() do
			local n1 = buf(i+12,2):le_uint()
			local n2 = buf(i+14+n1,2):le_uint()
			local clientlen = 16+n1+n2
			local client = msgdata:add(jamulus, buf(i, clientlen), "Client " .. c)
			client:add_le(fields.chanid, buf(i,1)); i=i+1
			client:add_le(fields.country, buf(i,2)); i=i+2
			client:add_le(fields.instrument, buf(i,4)); i=i+4
			client:add_le(fields.skill, buf(i,1)); i=i+1
			client:add_le(fields.ipaddr, buf(i,4)); i=i+4
			n = buf(i,2):le_uint(); i=i+2
			if n > 0 then client:add(fields.name, buf(i, n)); i=i+n end
			n = buf(i,2):le_uint(); i=i+2
			if n > 0 then client:add(fields.city, buf(i, n)); i=i+n end
			c = c+1
		end
		local s = "s"
		if c == 1 then s = "" end
		pinfo.cols.info:append(" (" .. c .. " client" .. s .. ")")
	elseif opcode == opcodes.CHANNEL_INFOS then
		msgdata:add_le(fields.country, buf(0,2))
		msgdata:add_le(fields.instrument, buf(2,4))
		msgdata:add_le(fields.skill, buf(6,1))
		pinfo.cols.info:append(" (" .. countries_valstr[buf(0,2):le_uint()] .. ", " .. instruments_valstr[buf(2,4):le_uint()] .. ", " .. skills_valstr[buf(6,1):le_uint()])
		local i = 7
		n = buf(i,2):le_uint(); i=i+2
		if n > 0 then
			msgdata:add(fields.name, buf(i, n))
			pinfo.cols.info:append(", " .. buf(i, n):string())
			i=i+n
		end
		n = buf(i,2):le_uint(); i=i+2
		if n > 0 then
			msgdata:add(fields.city, buf(i, n))
			pinfo.cols.info:append(", " .. buf(i, n):string())
			i=i+n
		end
		pinfo.cols.info:append(")")
	elseif opcode == opcodes.OPUS_SUPPORTED then
		-- no data
	elseif opcode == opcodes.LICENCE_REQUIRED then
		msgdata:add_le(fields.licreq, buf)
		pinfo.cols.info:append(" (" .. buf:le_uint() .. ")")
	elseif opcode == opcodes.REQ_CHANNEL_LEVEL_LIST then
		msgdata:add_le(fields.chanlvlopt, buf)
		pinfo.cols.info:append(" (" .. buf:le_uint() .. ")")
	elseif opcode == opcodes.VERSION_AND_OS then
		msgdata:add_le(fields.os, buf(0,1))
		pinfo.cols.info:append(" (" .. opsys_valstr[buf(0,1):le_uint()])
		local i = 1
		n = buf(i,2):le_uint(); i=i+2
		if n > 0 then
			msgdata:add(fields.osver, buf(i, n))
			pinfo.cols.info:append(", " .. buf(i, n):string())
			i=i+n
		end
		pinfo.cols.info:append(")")
	elseif opcode == opcodes.CHANNEL_PAN then
		local pan = panValue(buf(1,2):le_uint())
		msgdata:add_le(fields.chanid, buf(0,1))
		msgdata:add_le(fields.pan, buf(1,2)):append_text(" (" .. pan .. ")")
		pinfo.cols.info:append(" ([" .. buf(0,1):le_uint() .. "] => " .. pan .. ")")
	elseif opcode == opcodes.MUTE_STATE_CHANGED then
		msgdata:add_le(fields.chanid, buf(0,1))
		msgdata:add_le(fields.mute, buf(1,1))
		pinfo.cols.info:append(" ([" .. buf(0,1):le_uint() .. "] => " .. muting_valstr[buf(1,1):le_uint()] .. ")")
	elseif opcode == opcodes.CLIENT_ID then
		msgdata:add_le(fields.chanid, buf(0,1))
		pinfo.cols.info:append(" (" .. buf(0,1):le_uint() .. ")")
	elseif opcode == opcodes.CLM_PING_MS then
		msgdata:add_le(fields.txtime, buf(0,4))
		pinfo.cols.info:append(" (" .. buf(0,4):le_uint() .. ")")
	elseif opcode == opcodes.CLM_PING_MS_WITHNUMCLIENTS then
		msgdata:add_le(fields.txtime, buf(0,4))
		msgdata:add_le(fields.nclients, buf(4,1))
		pinfo.cols.info:append(" (" .. buf(0,4):le_uint() .. ", " .. buf(4,1):le_uint() .. ")")
	elseif opcode == opcodes.CLM_SERVER_FULL then
		-- no data
	elseif opcode == opcodes.CLM_REGISTER_SERVER then
		msgdata:add_le(fields.port, buf(0,2))
		msgdata:add_le(fields.country, buf(2,2))
		msgdata:add_le(fields.maxclients, buf(4,1))
		msgdata:add_le(fields.permanent, buf(5,1))
		pinfo.cols.info:append(" (port=" .. buf(0,2):le_uint() .. ", " .. countries_valstr[buf(2,2):le_uint()] .. ", maxclients=" .. buf(4,1):le_uint() .. ", perm=" .. buf(5,1):le_uint())
		local i = 6
		n = buf(i,2):le_uint(); i=i+2
		if n > 0 then
			msgdata:add(fields.name, buf(i, n))
			pinfo.cols.info:append(", name=\"" .. buf(i,n):string() .. "\"")
			i=i+n
		end
		n = buf(i,2):le_uint(); i=i+2
		if n > 0 then
			msgdata:add(fields.ipaddrs, buf(i, n))
			pinfo.cols.info:append(", ipaddrs=\"" .. buf(i,n):string() .. "\"")
			i=i+n
		end
		n = buf(i,2):le_uint(); i=i+2
		if n > 0 then
			msgdata:add(fields.city, buf(i, n))
			pinfo.cols.info:append(", city=\"" .. buf(i,n):string() .. "\"")
			i=i+n
		end
		pinfo.cols.info:append(")")
	elseif opcode == opcodes.CLM_UNREGISTER_SERVER then
		-- no data
	elseif opcode == opcodes.CLM_SERVER_LIST then
		local c = 0
		local i = 0
		while i < buf:len() do
			local n1 = buf(i+10,2):le_uint()
			local n2 = buf(i+12+n1,2):le_uint()
			local n3 = buf(i+14+n1+n2,2):le_uint()
			local serverlen = 16+n1+n2+n3
			local server = msgdata:add(jamulus, buf(i,serverlen), "Server " .. c)
			server:add_le(fields.ipaddr, buf(i,4)); i=i+4
			server:add_le(fields.port, buf(i,2)); i=i+2
			server:add_le(fields.country, buf(i,2)); i=i+2
			server:add_le(fields.maxclients, buf(i,1)); i=i+1
			server:add_le(fields.permanent, buf(i,1)); i=i+1
			n = buf(i,2):le_uint(); i=i+2
			if n > 0 then server:add(fields.name, buf(i, n)); i=i+n end
			n = buf(i,2):le_uint(); i=i+2
			if n > 0 then server:add(fields.ipaddrs, buf(i, n)); i=i+n end
			n = buf(i,2):le_uint(); i=i+2
			if n > 0 then server:add(fields.city, buf(i, n)); i=i+n end
			c = c+1
		end
		local s = "s"
		if c == 1 then s = "" end
		pinfo.cols.info:append(" (" .. c .. " server" .. s .. ")")
	elseif opcode == opcodes.CLM_REQ_SERVER_LIST then
		-- no data
	elseif opcode == opcodes.CLM_SEND_EMPTY_MESSAGE then
		msgdata:add_le(fields.ipaddr, buf(0,4))
		msgdata:add_le(fields.port, buf(4,2))
		pinfo.cols.info:append(" (" ..  tostring(buf(0,4):le_ipv4()) ..  ":" .. buf(4,2):le_uint() .. ")")
	elseif opcode == opcodes.CLM_EMPTY_MESSAGE then
		-- no data
	elseif opcode == opcodes.CLM_DISCONNECTION then
		-- no data
	elseif opcode == opcodes.CLM_VERSION_AND_OS then
		msgdata:add_le(fields.os, buf(0,1))
		pinfo.cols.info:append(" (" .. opsys_valstr[buf(0,1):le_uint()])
		local i = 1
		n = buf(i,2):le_uint(); i=i+2
		if n > 0 then
			msgdata:add(fields.osver, buf(i, n))
			pinfo.cols.info:append(", " .. buf(i, n):string())
			i=i+n
		end
		pinfo.cols.info:append(")")
	elseif opcode == opcodes.CLM_REQ_VERSION_AND_OS then
		-- no data
	elseif opcode == opcodes.CLM_CONN_CLIENTS_LIST then
		local c = 0
		local i = 0
		while i < buf:len() do
			local n1 = buf(i+12,2):le_uint()
			local n2 = buf(i+14+n1,2):le_uint()
			local clientlen = 16+n1+n2
			local client = msgdata:add(jamulus, buf(i, clientlen), "Client " .. c); c=c+1
			client:add_le(fields.chanid, buf(i,1)); i=i+1
			client:add_le(fields.country, buf(i,2)); i=i+2
			client:add_le(fields.instrument, buf(i,4)); i=i+4
			client:add_le(fields.skill, buf(i,1)); i=i+1
			client:add_le(fields.ipaddr, buf(i,4)); i=i+4
			n = buf(i,2):le_uint()
			client:add_le(fields.len, buf(i,2)); i=i+2
			if n > 0 then client:add(fields.name, buf(i, n)); i=i+n end
			n = buf(i,2):le_uint()
			client:add_le(fields.len, buf(i,2)); i=i+2
			if n > 0 then client:add(fields.city, buf(i, n)); i=i+n end
		end
		local s = "s"
		if c == 1 then s = "" end
		pinfo.cols.info:append(" (" .. c .. " client" .. s .. ")")
	elseif opcode == opcodes.CLM_REQ_CONN_CLIENTS_LIST then
		-- no data
	elseif opcode == opcodes.CLM_CHANNEL_LEVEL_LIST then
		local levels = msgdata:add(fields.levels, buf)
		local i = 0
		local desc = ""
		while i < buf:len() do
			local l1 = buf(i,1):le_uint()
			local l2 = bit.rshift(l1, 4)
			l1 = bit.band(l1, 15);
			if desc == "" then
				desc = " ("
			else
				desc = desc .. ","
			end
			if l1 == 15 then l1 = "-" end
			if l2 == 15 then l2 = "-" end
			desc = desc .. l1 .. "," .. l2
			-- levels:add(fields.level, buf(i,1), l1);
			-- levels:add(fields.level, buf(i,1), l2);
			i = i + 1
		end
		if desc ~= "" then levels:append_text(desc .. ")") end
	elseif opcode == opcodes.CLM_REGISTER_SERVER_RESP then
		msgdata:add_le(fields.status, buf)	-- 0 = success, 1 = server full
		pinfo.cols.info:append(" (" .. status_valstr[buf:le_uint()] .. ")")
	else
		-- msgdata:add(fields.data, buf)
	end
end


--------------------------------------------------------------------------------
-- We want to have our protocol dissection invoked for a specific UDP port,
-- so get the UDP dissector table and add our protocol to it.
local function enableDissector()
    -- using DissectorTable:set() removes existing dissector(s), whereas the
    -- DissectorTable:add() one adds ours before any existing ones, but
    -- leaves the other ones alone, which is better
    local udp_port = DissectorTable.get("udp.port")
    for port = default_settings.port1, default_settings.port2 do
	    udp_port:add(port, jamulus)
    end
end
-- call it now, because we're enabled by default
enableDissector()

local function disableDissector()
    local udp_port = DissectorTable.get("udp.port")
    for port = default_settings.port1, default_settings.port2 do
	    udp_port:remove(port, jamulus)
    end
end


--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

----------------------------------------
-- register our preferences
jamulus.prefs.enabled     = Pref.bool("Dissector enabled", default_settings.enabled,
                                        "Whether the FPM dissector is enabled or not")

jamulus.prefs.debug       = Pref.enum("Debug", default_settings.debug_level,
                                        "The debug printing level", debug_pref_enum)

----------------------------------------
-- the function for handling preferences being changed
function jamulus.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.debug_level = jamulus.prefs.debug
    resetDebugLevel()

    if default_settings.enabled ~= jamulus.prefs.enabled then
        default_settings.enabled = jamulus.prefs.enabled
        if default_settings.enabled then
            enableDissector()
        else
            disableDissector()
        end
        -- have to reload the capture file for this type of change
        reload()
    end

end

dprint2("jamulus Prefs registered")
