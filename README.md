# Readme

## Motivation and Warning
Matrix and Riot support cross-signing now. Unfortunately the current support in
Riot only offers the option to perform interactive verification. This does not
work too well for people who only interact online and need to perform
verification through another messaging system. It also does not support a TOFU
model, a "certificate authority" or a web of trust approach.

This tool is intended to help with that. It is very much experimental and may
cause cancer, set your computer on fire, require the sacrifice of your
firstborn or cause mild indigestion. You have been warned.

## Dependencies

* Python (>= 3.7)
* base58 (>= 2.0.1)
* cryptography (>= 2.9.2)
* requests (>= 2.24.0)
