# Bitcoin Test Wallets Generator

A Bitcoin wallets generator to help bitcoin programmers.   


## Features

* Generate six wallets (Alice, Bob, Carol, Dave Eve, Mallory)
* Create a json file with all cryptographic materials
* Import private keys to Bitcoin Core


## Requirements

NodeJS v10   
Bash or a Bash interpreter like Cygwin or Windows Subsystem for Linux (WSL)   


## How to use it

Install dependencies
```
$ npm install
```

If necessary, change the entropy for each wallet at the beginning of [generate_wallets.js](./generate_wallets.js)   
16 bytes entropy = 12 words mnemonic   
32 bytes entropy = 24 words mnemonic   
```
$ npm run entropy 16
```

Launch Bitcoin Core so that we can import the private keys.   

Run the script
```
$ node generate_wallets.js
```