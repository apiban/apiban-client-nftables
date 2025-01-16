# apiban-client-nftables

[apiban](https://www.apiban.org) nftables go client

**APIBAN is made possible by the generosity of our [sponsors](https://apiban.org/doc.html#sponsors).**

## Beta

This software, _if you can even call it that_, has limited testing, running on only the systems of the developers. We encourage testing and gladly accept contributions, issues, and comments.

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

#### Example Ruleset (with example IPs)

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

## More Info

* Sets: <https://wiki.nftables.org/wiki-nftables/index.php/Sets>
* APIBAN: <https://www.apiban.org>
