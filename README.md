# apiban-client-nftables

[apiban](https://www.apiban.org) nftables go client

> [!IMPORTANT]
> APIBAN is made possible by the generosity of our [sponsors](https://apiban.org/doc.html#sponsors).

## Beta

This software, _if you can even call it that_, has limited testing, running on only the systems of the developers. We encourage testing and gladly accept contributions, issues, and comments.

## Contents

- [Using apiban-client-nftables](#using-apiban-client-nftables)
  - [Concept/Background](#conceptbackground)
    - [example ruleset](#example-ruleset)
  - [Using the client](#using-the-client)
    - [Example Install](#example-install)
  - [Log Rotation](#log-rotation)
  - [Crontab](#crontab)
  - [FLUSHAFTER](#flushafter)
  - [UPTIME](#uptime)
  - [YaML](#yaml)
  - [Log](#log)
  - [TLS Verify](#tls-verify)
  - [Counters](#counters)
- [More Info](#more-info)
- [License](#license)
- [Contributions](#contributions)

## Using apiban-client-nftables

### Concept/Background

nftables is something many of us do not have familiarity with when compared to iptables (the "main" [apiban client](https://github.com/apiban/apiban-client-nftables) is iptables based). With the current SIP/HTTP dataset having (sometimes) several thousand active IP addresses, the community has asked for a simple way to use nftables with APIBAN.

This client will add active IPs to a nftable set.

> [!NOTE]
> If there is no found set, the client will look for an input chain and an output chain; making a set in the related table. The client will then attempt to add a rule to both the input chain (blocking from the source ip) and the outbound chain (blocking to the destination ip).

You can have this set wherever you like... just let the client know the `setname` in `config.json`. A set named **APIBAN** is what we use here, so in the config this looks like:

```json
    "setname": "APIBAN"
```

To create this set, run a command such as:

```
nft add set inet filter APIBAN { type ipv4_addr\; }
```

This assumes your table is called `filter` (which is the default installed). Regardless, add it where you want.

Then, add your set to the chain of your choosing, such as:

```
nft add rule inet filter input ip saddr @APIBAN drop
nft add rule inet filter output ip daddr != @APIBAN accept
```

(blocking inbound and outbound traffic)

#### Example Ruleset

```
# nft list ruleset
table inet filter {
	set APIBAN {
		type ipv4_addr
		elements = { 192.168.0.1, 192.168.0.2,
			     192.168.0.1, ...}
	}

	chain input {
		type filter hook input priority filter; policy accept;
		ip saddr @APIBAN drop
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
	}

	chain output {
		type filter hook output priority filter; policy accept;
		ip daddr != @APIBAN accept
	}
}
```

### Using the client

1. Create the folder `/usr/local/bin/apiban`
2. Download apiban-client-nftables to `/usr/local/bin/apiban/`
3. Download config.json to `/usr/local/bin/apiban/`
4. Using your favorite text editor, update config.json with your APIBAN key
5. Give apiban-client-nftables execute permission
6. Test

#### Example Install

```
mkdir /usr/local/bin/apiban 
cd /usr/local/bin/apiban    
wget https://github.com/apiban/apiban-client-nftables/raw/refs/heads/main/apiban-client-nftables  
wget https://github.com/apiban/apiban-client-nftables/raw/refs/heads/main/config.json
vi config.json
chmod +x /usr/local/bin/apiban/apiban-client-nftables
/usr/local/bin/apiban/apiban-client-nftables
```

### Log Rotation

```
cat > /etc/logrotate.d/apiban-client-nftables << EOF
/var/log/apiban-nft-client.log {
        daily
        copytruncate
        rotate 7
        compress
}
EOF
```

### Crontab

Example crontab running every 4 min...

```
# update apiban nftables
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/4 * * * * /usr/local/bin/apiban/apiban-client-nftables >/dev/null 2>&1
```

### FLUSHAFTER

**New Feature**: added 2025-06-26

In the `config.json` is a new item:

```json
    "flushafter": 604800,
```

This is the period, in seconds, to keep addresses blocked. The default period, 604800, is one (1) week. If you wanted to retain addresses for 4 weeks, you would set this to `2419200`.

You can manually flush addresses and replace with the currently active address by running:

`/usr/local/bin/apiban/apiban-client-nftables FULL`

### UPTIME

**New Feature**: added 2026-03-18

In the `config.json` is a new item:

```json
    "uptime": 600,
```

This is the period, in seconds, for which a FULL pull of blocked ip's is downloaded. This is useful for when the system is rebooted. If the system uptime is less than the setting, a full pull is conducted. The default value is 600 (5 minutes).

### YAML

**New Feature**: added 2025-11-03

apiban-client-nftables supports yaml instead of json, for those who want one over the other for whatever reason.

The client will automatically convert a json config to yaml (and vice versa) if the `yaml` flag is sent to the executable.

Example:

`apiban-client-nftables -yaml=true`

or in crontab:

```
# update apiban nftables
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/4 * * * * /usr/local/bin/apiban/apiban-client-nftables -yaml=true >/dev/null 2>&1
```

### Log

The default log location is `/var/log/apiban-nft-client.log`. This can be updated with the `log` flag:

Example:

`apiban-client-nftables -yaml=true -log=/opt/loggity-log.txt`

### TLS verify

If for whatever reason you want to skip TLS verification, there's a flag for it: `verify`. (defaults to true)

Example:

`apiban-client-nftables -yaml=true -verify=false`

### COUNTERS

**New Feature**: added 2026-05-08 (requested by @tsearle)

apiban-client-nftables can now create the APIBAN nft set with counters enabled.

Example:

`apiban-client-nftables -counter=true`

or in crontab:

```
# update apiban nftables
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/4 * * * * /usr/local/bin/apiban/apiban-client-nftables -yaml=true -counter=true >/dev/null 2>&1
```

## More Info

* Sets: <https://wiki.nftables.org/wiki-nftables/index.php/Sets>
* APIBAN: <https://www.apiban.org>

## License

`GPLv3`

Copyright: Fred Posner ([Palner](https://www.palner.com/))

## Contributions

Contributions are welcome!

Fork and do pull requests:
<https://github.com/apiban/apiban-client-nftables>