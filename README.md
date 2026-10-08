# SubnetCalc

Advanced IPv4/IPv6 subnet calculator — Python CLI + GitHub Pages web app.

## 🌐 Web App (GitHub Pages)

Live at: `https://<your-username>.github.io/<repo-name>/`

All features run in pure JavaScript — no backend needed.

**Features:**
- Network info (CIDR, mask, wildcard, binary mask, hex, class, type)
- Subnetting — divide by count or by required hosts
- VLSM — named segment allocation with visual map
- Summarize/collapse multiple networks into supernets
- IP range → CIDR blocks
- IPv6 info (expand, compress, type detection)
- One-click copy for all outputs

## 🐍 Python CLI (`subnet_calc.py`)

**Requirements:** Python 3.9+ (no external libraries)

```bash
python subnet_calc.py --help
```

### Commands

```bash
# Full network info
python subnet_calc.py info 192.168.1.0/24
python subnet_calc.py info 10.0.0.0/255.0.0.0          # dotted mask
python subnet_calc.py info 10.0.0.0/0.255.255.255       # wildcard
python subnet_calc.py info 2001:db8::/32                 # IPv6

# Subnetting
python subnet_calc.py subnet 192.168.1.0/24 --count 4
python subnet_calc.py subnet 10.0.0.0/16 --hosts 500

# VLSM allocation
python subnet_calc.py vlsm 10.0.0.0/24 Eng:50 HR:20 IT:100 Mgmt:10

# Summarize/collapse
python subnet_calc.py summarize 192.168.1.0/25 192.168.1.128/25

# IP range to CIDRs
python subnet_calc.py range 10.0.0.1 10.0.0.254

# Output formats
python subnet_calc.py info 192.168.1.0/24 --output json
python subnet_calc.py subnet 10.0.0.0/16 --count 8 --output csv
```
