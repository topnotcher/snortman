require_relative 'parse'

disable_files = %w{
	compromised.rules
	emerging-games.rules
	emerging-icmp.rules
	emerging-icmp.rules
	emerging-icmp_info.rules
	emerging-inappropriate.rules
	emerging-p2p.rules
	emerging-shellcode.rules
	emerging-snmp.rules
	emerging-tftp.rules
	tor.rules
	emerging-netbios.rules
	emerging-p2p.rules
	decoder-events.rules
	http-events.rules
	smtp-events.rules
	stream-events.rules
	tls-events.rules
	emerging-info.rules
	ciarmy.rules
	emerging-deleted.rules
	drop.rules
}


manager = RulesManager.new
manager.add_directory('rules')

disable_files.each {|file| manager.disable_file file}

# sipvicious
manager.disable_sid 2011766
manager.disable_sid 2011716
manager.disable_sid 2012204

# inbound to port 3306
manager.disable_sid 2010937

# Google music
manager.disable_sid 2012935

# iOS MITM
manager.disable_sid 2013407

# RDP connection noise
manager.disable_sid 2001329
manager.disable_sid 2001330

# Cyberkit ping windows
manager.disable_sid 2100483

# Sogou
manager.disable_sid 2011719

#  grep -E '(ET|GPL) CHAT (MISC|AIM|Skype|Google|Facebook|Jabber|ICQ|Yahoo)' rules/emerging-chat.rules | sed -re 's/.*msg:"([^"]+)".*sid:([0-9]+).*/\n# \1\nmanager.disable_sid \2/' 

# ET CHAT Facebook Chat (send message)
manager.disable_sid 2010784

# ET CHAT Facebook Chat (buddy list)
manager.disable_sid 2010785

# ET CHAT Facebook Chat (settings)
manager.disable_sid 2010786

# ET CHAT Facebook Chat using XMPP
manager.disable_sid 2010819

# ET CHAT ICQ Status Invisible
manager.disable_sid 2001801

# ET CHAT ICQ Status Change (1)
manager.disable_sid 2001802

# ET CHAT ICQ Status Change (2)
manager.disable_sid 2001803

# ET CHAT ICQ Login
manager.disable_sid 2001804

# ET CHAT ICQ Message
manager.disable_sid 2001805

# ET CHAT Google Talk (Jabber) Client Login
manager.disable_sid 2002327

# ET CHAT Google IM traffic Jabber client sign-on
manager.disable_sid 2002334

# ET CHAT Yahoo IM voicechat
manager.disable_sid 2001254

# ET CHAT Yahoo IM ping
manager.disable_sid 2001255

# ET CHAT Yahoo IM conference invitation
manager.disable_sid 2001256

# ET CHAT Yahoo IM conference logon success
manager.disable_sid 2001257

# ET CHAT Yahoo IM conference message
manager.disable_sid 2001258

# ET CHAT Yahoo IM Unavailable Status
manager.disable_sid 2001427

# ET CHAT Yahoo IM file transfer request
manager.disable_sid 2001259

# ET CHAT Yahoo IM message
manager.disable_sid 2001260

# ET CHAT Yahoo IM conference offer invitation
manager.disable_sid 2001262

# ET CHAT Yahoo IM conference request
manager.disable_sid 2001263

# ET CHAT Yahoo IM conference watch
manager.disable_sid 2001264

# ET CHAT Yahoo IM Client Install
manager.disable_sid 2002659

# ET CHAT Skype VOIP Checking Version (Startup)
manager.disable_sid 2001595

# ET CHAT Skype User-Agent detected
manager.disable_sid 2002157

# ET CHAT Skype Bootstrap Node (udp)
manager.disable_sid 2003022

# GPL CHAT AIM receive message
manager.disable_sid 2101633

# GPL CHAT Yahoo IM conference invitation
manager.disable_sid 2102453

# GPL CHAT Yahoo IM conference logon success
manager.disable_sid 2102454

# GPL CHAT Yahoo IM successful chat join
manager.disable_sid 2102458

# GPL CHAT Yahoo IM voicechat
manager.disable_sid 2102451

# GPL CHAT Yahoo Messenger File Transfer Receive Request
manager.disable_sid 2102456

# GPL CHAT Yahoo IM conference watch
manager.disable_sid 2102461

# GPL CHAT Jabber/Google Talk Incoming Message
manager.disable_sid 2100236

# GPL CHAT Jabber/Google Talk Logon Success
manager.disable_sid 2100235

# GPL CHAT AIM login
manager.disable_sid 2101631

# GPL CHAT AIM send message
manager.disable_sid 2101632

# GPL CHAT Google Talk Version Check
manager.disable_sid 2100876

# GPL CHAT Yahoo IM conference message
manager.disable_sid 2102455

# GPL CHAT Yahoo IM conference offer invitation
manager.disable_sid 2102459

# GPL CHAT Yahoo IM ping
manager.disable_sid 2102452

# GPL CHAT Yahoo IM conference request
manager.disable_sid 2102460

# GPL CHAT Google Talk Logon
manager.disable_sid 2100232

# GPL CHAT Google Talk Startup
manager.disable_sid 2100877

# GPL CHAT Jabber/Google Talk Log Out
manager.disable_sid 2100234

# GPL CHAT Jabber/Google Talk Outgoing Auth
manager.disable_sid 2100231

# GPL CHAT MISC Jabber/Google Talk Outgoing Traffic
manager.disable_sid 2100230

# GPL CHAT Jabber/Google Talk Outoing Message
manager.disable_sid 2100233

# GPL CHAT ICQ access
manager.disable_sid 2100541

#grep -E 'ET POLICY (TeamViewer|iTunes|Google Talk|Yahoo Mail|Logmein|Protocol 41|Dropbox.com|DropBox|GNU/Linux APT|GNU/Linux YUM|Kindle Fire|Microsoft Online Storage|Pandora|Maxmind|W32/BitCoinMiner.MultiThreat)' rules/emerging-policy.rules | sed -re 's/.*msg:"([^"]+)".*sid:([0-9]+).*/\n# \1\nmanager.disable_sid \2/'

# ET POLICY TeamViewer Dyngate User-Agent
manager.disable_sid 2009475

# ET POLICY Google Talk TLS Client Traffic
manager.disable_sid 2002330

# ET POLICY iTunes User Agent
manager.disable_sid 2002878

# ET POLICY Logmein.com Host List Download
manager.disable_sid 2007765

# ET POLICY Logmein.com Update Activity
manager.disable_sid 2007766

# ET POLICY TeamViewer Keep-alive outbound
manager.disable_sid 2008794

# ET POLICY TeamViewer Keep-alive inbound
manager.disable_sid 2008795

# ET POLICY Yahoo Mail Message Send
manager.disable_sid 2000044

# ET POLICY Yahoo Mail General Page View
manager.disable_sid 2000341

# ET POLICY Logmein.com/Join.me SSL Remote Control Access
manager.disable_sid 2014756

# ET POLICY Protocol 41 IPv6 encapsulation potential 6in4 IPv6 tunnel active
manager.disable_sid 2012141

# ET POLICY Dropbox.com Offsite File Backup in Use
manager.disable_sid 2012647

# ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management
manager.disable_sid 2013504

# ET POLICY GNU/Linux YUM User-Agent Outbound likely related to package management
manager.disable_sid 2013505

# ET POLICY Kindle Fire Browser User-Agent Outbound
manager.disable_sid 2014095

# ET POLICY Microsoft Online Storage Client Hello TLSv1 Possible SkyDrive (1)
manager.disable_sid 2014919

# ET POLICY Microsoft Online Storage Client Hello TLSv1 Possible SkyDrive (2)
manager.disable_sid 2014920

# ET POLICY Pandora Usage
manager.disable_sid 2014997

# ET POLICY Maxmind geoip check to /app/geoip.js
manager.disable_sid 2015878

# ET POLICY DropBox User Content Access over SSL
manager.disable_sid 2017015

# ET POLICY W32/BitCoinMiner.MultiThreat Subscribe/Authorize Stratum Protocol Message
manager.disable_sid 2017871

# ET POLICY W32/BitCoinMiner.MultiThreat Stratum Protocol Mining.Notify Initial Connection Server Response
manager.disable_sid 2017872

# ET POLICY W32/BitCoinMiner.MultiThreat Stratum Protocol Mining.Notify Work Server Response
manager.disable_sid 2017873

# ET POLICY W32/BitCoinMiner.MultiThreat Getblocktemplate Protocol Server Connection
manager.disable_sid 2017878

# ET POLICY W32/BitCoinMiner.MultiThreat Getblocktemplate Protocol Server Coinbasetxn Begin Mining Response
manager.disable_sid 2017879

#grep 'ET MALWARE SOCKS' rules/emerging-malware.rules| sed -re 's/.*msg:"([^"]+)".*sid:([0-9]+).*/\n# \1\nmanager.disable_sid \2/'

# ET MALWARE SOCKSv5 Port 25 Inbound Request (Windows Source)
manager.disable_sid 2003254

# ET MALWARE SOCKSv5 Port 25 Inbound Request (Linux Source)
manager.disable_sid 2003255

# ET MALWARE SOCKSv4 Port 25 Inbound Request (Windows Source)
manager.disable_sid 2003256

# ET MALWARE SOCKSv5 Port 25 Inbound Request (Linux Source)
manager.disable_sid 2003257

# ET MALWARE SOCKSv5 DNS Inbound Request (Windows Source)
manager.disable_sid 2003258

# ET MALWARE SOCKSv5 DNS Inbound Request (Linux Source)
manager.disable_sid 2003259

# ET MALWARE SOCKSv5 HTTP Proxy Inbound Request (Windows Source)
manager.disable_sid 2003260

# ET MALWARE SOCKSv5 HTTP Proxy Inbound Request (Linux Source)
manager.disable_sid 2003261

# ET MALWARE SOCKSv4 HTTP Proxy Inbound Request (Windows Source)
manager.disable_sid 2003262

# ET MALWARE SOCKSv4 HTTP Proxy Inbound Request (Linux Source)
manager.disable_sid 2003263

# ET MALWARE SOCKSv5 Port 443 Inbound Request (Windows Source)
manager.disable_sid 2003266

# ET MALWARE SOCKSv5 Port 443 Inbound Request (Linux Source)
manager.disable_sid 2003267

# ET MALWARE SOCKSv4 Port 443 Inbound Request (Windows Source)
manager.disable_sid 2003268

# ET MALWARE SOCKSv4 Port 443 Inbound Request (Linux Source)
manager.disable_sid 2003269

# ET MALWARE SOCKSv5 Port 5190 Inbound Request (Windows Source)
manager.disable_sid 2003270

# ET MALWARE SOCKSv5 Port 5190 Inbound Request (Linux Source)
manager.disable_sid 2003271

# ET MALWARE SOCKSv4 Port 5190 Inbound Request (Windows Source)
manager.disable_sid 2003272

# ET MALWARE SOCKSv4 Port 5190 Inbound Request (Linux Source)
manager.disable_sid 2003273

# ET MALWARE SOCKSv5 Port 1863 Inbound Request (Windows Source)
manager.disable_sid 2003274

# ET MALWARE SOCKSv5 Port 1863 Inbound Request (Linux Source)
manager.disable_sid 2003275

# ET MALWARE SOCKSv4 Port 1863 Inbound Request (Windows Source)
manager.disable_sid 2003276

# ET MALWARE SOCKSv4 Port 1863 Inbound Request (Linux Source)
manager.disable_sid 2003277

# ET MALWARE SOCKSv5 Port 5050 Inbound Request (Windows Source)
manager.disable_sid 2003278

# ET MALWARE SOCKSv5 Port 5050 Inbound Request (Linux Source)
manager.disable_sid 2003279

# ET MALWARE SOCKSv4 Port 5050 Inbound Request (Windows Source)
manager.disable_sid 2003280

# ET MALWARE SOCKSv4 Port 5050 Inbound Request (Linux Source)
manager.disable_sid 2003281

# ET MALWARE SOCKSv5 IPv6 Inbound Connect Request (Windows Source)
manager.disable_sid 2003284

# ET MALWARE SOCKSv5 IPv6 Inbound Connect Request (Linux Source)
manager.disable_sid 2003285

# ET MALWARE SOCKSv5 UDP Proxy Inbound Connect Request (Windows Source)
manager.disable_sid 2003286

# ET MALWARE SOCKSv5 UDP Proxy Inbound Connect Request (Linux Source)
manager.disable_sid 2003287

# ET MALWARE SOCKSv4 Bind Inbound (Windows Source)
manager.disable_sid 2003288

# ET MALWARE SOCKSv4 Bind Inbound (Linux Source)
manager.disable_sid 2003289

# ET MALWARE SOCKSv5 Bind Inbound (Linux Source)
manager.disable_sid 2003290

# ET MALWARE SOCKSv5 Bind Inbound (Windows Source)
manager.disable_sid 2003291

# ET POLICY DNS Update from External net
manager.disable_sid 2009702

# ET POLICY Unusual number of DNS No Such Name Responses
manager.disable_sid 2003195

# ET POLICY Outdated Windows Flash Version IE
#  looks like only really hitting on URI_Open
manager.disable_sid 2014726

# ET POLICY Vulnerable Java Version 1.6.x Detected
manager.disable_sid 2011582

# ET POLICY Vulnerable Java Version 1.8.x Detected
manager.disable_sid 2019401

# ET POLICY Unsupported/Fake Internet Explorer Version MSIE 5
# mostly uri_open
manager.disable_sid 2016870

# ET POLICY MOBILE Apple device leaking UDID from SpringBoard via GET
manager.disable_sid 2013290

# ET DNS Non-DNS or Non-Compliant DNS traffic on DNS port Reserved Bit Set - Likely Kazy
manager.disable_sid 2014703

# ET POLICY Inbound Frequent Emails - Possible Spambot Inb
manager.disable_sid 2002087

# ET SCAN Potential VNC Scan 5900-5920
manager.disable_sid 2002911

# ET POLICY User-Agent (NSIS_Inetc (Mozilla)) - Sometimes used by hostile installers
manager.disable_sid 2011227

# ET POLICY Http Client Body contains pwd= in cleartext
manager.disable_sid 2012888

# ET POLICY Http Client Body contains pw= in cleartext
manager.disable_sid 2012889

# ET POLICY User-Agent (Launcher)
manager.disable_sid 2010645

# ET MALWARE MarketScore.com Spyware User Configuration and Setup Access User-Agent (OSSProxy)
manager.disable_sid 2001562

# ET MALWARE MarketScore.com Spyware Proxied Traffic
manager.disable_sid 2001564

# ET POLICY Python-urllib/ Suspicious User Agent
manager.disable_sid 2013031

# ET SCAN Potential SSH Scan
manager.disable_sid 2001219

# ET TROJAN MS Terminal Server User A Login, possible Morto inbound
manager.disable_sid 2013497

# ET SCAN Sipvicious Scan
manager.disable_sid 2008578

# ET MALWARE Sogoul.com Spyware User-Agent (SogouIMEMiniSetup)
manager.disable_sid 2008500

# ET CURRENT_EVENTS DNS Amplification Attack Inbound
manager.disable_sid 2016016

# ET POLICY Suspicious inbound to PostgreSQL port 5432
manager.disable_sid 2010939

# ET MALWARE QVOD Related Spyware/Malware User-Agent (Qvod)
manager.disable_sid 2009785

# GPL IMAP fetch overflow attempt
manager.disable_sid 2103070

# ET SCAN Rapid POP3 Connections - Possible Brute Force Attack
manager.disable_sid 2002992

# ET SCAN Potential FTP Brute-Force attempt
manager.disable_sid 2002383

# ET POLICY Windows-Based OpenSSL Tunnel Outbound
manager.disable_sid 2012078

# ET USER_AGENTS Suspicious User Agent (agent)
manager.disable_sid 2001891

# ET MALWARE Suspicious Mozilla User-Agent - Likely Fake (Mozilla/4.0)
manager.disable_sid 2003492

# ET DOS Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests IMPL 0x03
manager.disable_sid 2017919

# ET DOS Possible NTP DDoS Multiple MON_LIST Seq 0 Response Spanning Multiple Packets IMPL 0x03
manager.disable_sid 2017921

# ET POLICY Cleartext WordPress Login
manager.disable_sid 2012843

# ET POLICY Http Client Body contains pass= in cleartext
manager.disable_sid 2012887

# ET POLICY Outgoing Basic Auth Base64 HTTP Password detected unencrypted
manager.disable_sid 2006380

# ET POLICY Incoming Basic Auth Base64 HTTP Password detected unencrypted
manager.disable_sid 2006402

# ET CINS Active Threat Intelligence Poor Reputation IP group 12
manager.disable_sid 2403311

# ET CINS Active Threat Intelligence Poor Reputation IP group 18
manager.disable_sid 2403317

# ET CINS Active Threat Intelligence Poor Reputation IP group 3
manager.disable_sid 2403302

# ET DROP Dshield Block Listed Source group 1
manager.disable_sid 2402000

# ET CINS Active Threat Intelligence Poor Reputation IP group 1
manager.disable_sid 2403300

# GPL DNS named version attempt
manager.disable_sid 2101616

# ET POLICY TLS possible TOR SSL traffic
manager.disable_sid 2018789

# ET MALWARE User-Agent (Mozilla/4.0 (compatible))
manager.disable_sid 2008974

# ET POLICY OpenVPN Update Check
manager.disable_sid 2014799

# ET CURRENT_EVENTS Possible TLS HeartBleed Unencrypted Request Method 3 (Inbound to Common SSL Port)
manager.disable_sid 2018389

# ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack!
manager.disable_sid 2006546

# ET SCAN LibSSH2 Based SSH Connection - Often used as a BruteForce Tool
manager.disable_sid 2018689

# ET SCAN LibSSH Based SSH Connection - Often used as a BruteForce Tool
manager.disable_sid 2006435

# GPL TELNET Bad Login
manager.disable_sid 2101251

# ET POLICY Application Crash Report Sent to Microsoft
manager.disable_sid 2018170

# ET CURRENT_EVENTS JCE Joomla Scanner 
manager.disable_sid 2016032

# ET WEB_SPECIFIC_APPS JCE Joomla Extension
manager.disable_sid 2018326

# GPL WEB_SERVER apache ?M=D directory list attempt
manager.disable_sid 2101519

# GPL WEB_SERVER 403 Forbidden
manager.disable_sid 2101201

# ET POLICY Bitcoin Mining Extensions Header
manager.disable_sid 2016758

# ET POLICY Possible BitCoin Miner User-Agent (miner)
manager.disable_sid 2016067

# ET POLICY MOBILE Apple device leaking UDID from SpringBoard
manager.disable_sid 2013289

# ET CHAT MSN IM Poll via HTTP
manager.disable_sid 2001682

# ET CHAT General MSN Chat Activity
manager.disable_sid 2009375

# GPL SCAN SolarWinds IP scan attempt
manager.disable_sid 2101918

# ET TROJAN DNS Reply for unallocated address space - Potentially Malicious 1.1.1.0/24
manager.disable_sid 2016104

# ET POLICY PE EXE or DLL Windows file download HTTP
manager.disable_sid 2018959

# GPL IMAP unsubscribe overflow attempt
manager.disable_sid 2103076

# GPL IMAP status overflow attempt
manager.disable_sid 2103072

# ET DNS DNS Lookup for localhost.DOMAIN.TLD
manager.disable_sid 2011802

# ET TROJAN DNS Reply for unallocated address space - Potentially Malicious 1.1.1.0/24
manager.disable_sid 2016104

# ET CHAT MSN Status Change
manager.disable_sid 2002192

# ET CHAT IRC PING command
manager.disable_sid 2002027

# ET CHAT IRC PONG command
manager.disable_sid 2002028

# GPL IMAP status overflow attempt
manager.disable_sid 2103072

# ET TROJAN DNS Reply Sinkhole - Anubis - 195.22.26.192/26
manager.disable_sid 2018455

# ET POLICY Vulnerable Java Version 1.7.x Detected
manager.disable_sid 2014297

# ET SCAN Rapid IMAPS Connections - Possible Brute Force Attack
manager.disable_sid 2002995

# ET WEB_CLIENT Hex Obfuscation of Script Tag % Encoding | FPs on narutoget.com
manager.disable_sid 2012263

# ET POLICY Windows Mobile 7.0 User-Agent detected
manager.disable_sid 2013784

# ET POLICY Windows 98 User-Agent Detected - Possible Malware or Non-Updated System
manager.disable_sid 2007695

# ET POLICY Microsoft user-agent automated process response to automated request
manager.disable_sid 2012692

# ET DOS Possible WordPress Pingback DDoS in Progress (Inbound)
manager.disable_sid 2018277

# ET WEB_SPECIFIC_APPS Possible WordpressPingbackPortScanner detected 
manager.disable_sid 2016061

# ET POLICY Unsupported/Fake Internet Explorer Version MSIE 4.
manager.disable_sid 2016871

manager.disable_sid 2013028 # ET POLICY curl User-Agent Outbound

manager.disable_sid 2014727 # ET POLICY Outdated Mac Flash Version

manager.disable_sid 2001331 # ET POLICY RDP disconnect request

manager.disable_sid 2000418 # ET POLICY Executable and linking format (ELF) file download

manager.disable_sid 2014932 # ET POLICY DynDNS CheckIp External IP Address Server Respons

manager.disable_sid 2013715 # ET POLICY BingBar ToolBar User-Agent (BingBar)

manager.disable_sid 2012692 # ET POLICY Microsoft user-agent automated process response to automated request

manager.disable_sid 2013414 # ET POLICY Executable served from Amazon S3

manager.disable_sid 2013926 # ET POLICY HTTP traffic on port 443 (POST)

manager.disable_sid 2014702 # ET DNS Non-DNS or Non-Compliant DNS traffic on DNS port Opcode 8 through 15 set - Likely Kazy

manager.disable_sid 2019416 # ET POLICY SSLv3 outbound connection from client vulnerable to POODLE attack

manager.disable_sid 2014384 # ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt

manager.disable_sid 2010066 # ET POLICY Data POST to an image file (gif)

manager.disable_sid 2012648 # ET POLICY Dropbox Client Broadcasting

manager.disable_sid 2015686 # ET POLICY Signed TLS Certificate with md5WithRSAEncryption

manager.disable_sid 2011507 # ET WEB_CLIENT PDF With Embedded File

manager.disable_sid 2001855 # ET MALWARE Fun Web Products Spyware User-Agent (FunWebProducts)

manager.disable_sid 2018383 # ET CURRENT_EVENTS Possible OpenSSL HeartBleed Large HeartBeat Response from Common SSL Port (Outbound from Client)

#% ps4 FPs
manager.disable_sid 2003927 # ET TROJAN Suspicious User-Agent (HTTPTEST) - Seen used by downloaders

#% SSDP blocked at border for non-server networks
manager.disable_sid 2019102 # ET DOS Possible SSDP Amplification Scan in Progress

manager.disable_sid 2100474 # GPL SCAN superscan echo

manager.disable_sid 2002910 # ET SCAN Potential VNC Scan 5800-5820

manager.disable_sid 2020565








manager.write_enabled('combined.rules','sid-msg.map')
