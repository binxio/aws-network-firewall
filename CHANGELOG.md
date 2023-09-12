# Changelog

<!--next-version-placeholder-->

## v0.10.2 (2023-09-12)

### Fix

* Flow value should not be quoted ([#24](https://github.com/binxio/aws-network-firewall/issues/24)) ([`0cc418d`](https://github.com/binxio/aws-network-firewall/commit/0cc418d16327a0e7c9ea361809dab6b97921afb4))

## v0.10.1 (2023-09-07)

### Fix

* Tls rules without endpoints ([#23](https://github.com/binxio/aws-network-firewall/issues/23)) ([`9e5dfa7`](https://github.com/binxio/aws-network-firewall/commit/9e5dfa7a6f4f47dfcebd129a1124ef3e5c921538))

## v0.10.0 (2023-08-09)

### Feature

* Calculate the used sid per type and region ([#17](https://github.com/binxio/aws-network-firewall/issues/17)) ([`5e3d5b3`](https://github.com/binxio/aws-network-firewall/commit/5e3d5b39fee2d28c1edc5de31419271e8edf7a33))

## v0.9.0 (2023-08-08)

### Feature

* Support aws prefix lists in suricata rules ([#15](https://github.com/binxio/aws-network-firewall/issues/15)) ([`ad55566`](https://github.com/binxio/aws-network-firewall/commit/ad555668c1cf277121bb9a6d2ddc7f86f98293a8))

## v0.8.0 (2023-08-07)

### Feature

* Generate rules for dns servers ([#14](https://github.com/binxio/aws-network-firewall/issues/14)) ([`c7ab409`](https://github.com/binxio/aws-network-firewall/commit/c7ab4090523be52f2d06a673c7d9525e762d0751))

## v0.7.3 (2023-08-07)

### Fix

* Restore the initial order of sid and rev ([#13](https://github.com/binxio/aws-network-firewall/issues/13)) ([`753705c`](https://github.com/binxio/aws-network-firewall/commit/753705c5f233ff3a064f7d9fb26b4eef0b897838))

## v0.7.2 (2023-07-31)

### Fix

* Implement handshake rule for non 443 ports with tls requirements ([#11](https://github.com/binxio/aws-network-firewall/issues/11)) ([`d2653e1`](https://github.com/binxio/aws-network-firewall/commit/d2653e1e0f81bf1cdee66076ae89bdede14b6118))

## v0.7.1 (2023-07-31)

### Fix

* Tls versions should be an array ([#10](https://github.com/binxio/aws-network-firewall/issues/10)) ([`d107514`](https://github.com/binxio/aws-network-firewall/commit/d1075147296ae4c68e82742b41bd4a0b4b41341f))

## v0.7.0 (2023-07-31)

### Feature

* Make tls version configurable per destination ([#9](https://github.com/binxio/aws-network-firewall/issues/9)) ([`bfe2ffa`](https://github.com/binxio/aws-network-firewall/commit/bfe2ffad70026272dc34a2b8f7e780ad0c4de403))

## v0.6.0 (2023-07-28)

### Feature

* Display rules per region ([#8](https://github.com/binxio/aws-network-firewall/issues/8)) ([`b089566`](https://github.com/binxio/aws-network-firewall/commit/b089566df82603c5c676791732ebddca1ace4cdb))

## v0.5.0 (2023-07-28)

### Feature

* Support custom messages ([#7](https://github.com/binxio/aws-network-firewall/issues/7)) ([`e946b2b`](https://github.com/binxio/aws-network-firewall/commit/e946b2b9853310587c7d05e85ea9a40de90f720f))

## v0.4.2 (2023-07-28)

### Fix

* Tls versions cannot be combined in a single rule ([#6](https://github.com/binxio/aws-network-firewall/issues/6)) ([`c1294a9`](https://github.com/binxio/aws-network-firewall/commit/c1294a9329043da3145eee0bdd5967c12954ccbd))

## v0.4.1 (2023-07-26)

### Fix

* Missing egress rules ([#5](https://github.com/binxio/aws-network-firewall/issues/5)) ([`6242cf4`](https://github.com/binxio/aws-network-firewall/commit/6242cf4988f007d29491c4295ded76c92b01c419))

## v0.4.0 (2023-07-26)

### Feature

* Support egress and inspection rule types ([#4](https://github.com/binxio/aws-network-firewall/issues/4)) ([`b32fc9b`](https://github.com/binxio/aws-network-firewall/commit/b32fc9bd7488607ad715a88b494d877715d032bc))

## v0.3.0 (2023-07-24)

### Feature

* Support rule types ([#3](https://github.com/binxio/aws-network-firewall/issues/3)) ([`af013d5`](https://github.com/binxio/aws-network-firewall/commit/af013d5e70511c8e4fc8bcbff78260e8e35d42b5))

## v0.2.0 (2023-07-24)

### Feature

* Support icmp rules ([#2](https://github.com/binxio/aws-network-firewall/issues/2)) ([`aa5d16f`](https://github.com/binxio/aws-network-firewall/commit/aa5d16f895f08323cd62812b2dddee78560ec79b))

## v0.1.2 (2023-07-20)

### Fix

* Update README.md to reflect correct project ([`93a8a23`](https://github.com/binxio/aws-network-firewall/commit/93a8a23c0a789c59c6c0009cbc497d20b4808e30))

## v0.1.1 (2023-07-20)

### Fix

* Release to pypi ([`fdf1b0f`](https://github.com/binxio/aws-network-firewall/commit/fdf1b0fd2809aef5b33ffb646776a715d0b93452))

## v0.1.0 (2023-07-20)

### Feature

* Limit on tls 1.2 and 1.3 by default ([`eccb490`](https://github.com/binxio/aws-network-firewall/commit/eccb490dfc52e6dcd0e10f9dd35b32f0fe81130a))
* Initial implementation ([`58c8bfd`](https://github.com/binxio/aws-network-firewall/commit/58c8bfdb384799d70c75c4bf83c55ded8bc914eb))
