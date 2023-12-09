# Thinkst Canarytokens Detector and Diffuser/Nullifier

A simple script to detect and remove [***Canary Tokens***](https://canarytokens.org/) 

![image](https://github.com/referefref/canarytokendetector/assets/56499429/0b62b080-90cb-45d9-ba29-47ba007d8399)

## Installation (tested on MacOS 14)
```bash
git clone https://github.com/referefref/canarytokendetector.git
cd canarytokendetector
brew install pdftk-java python3 python3-pip -y
pip3 install pefile
wget https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/disitool.py
```

## Examples

### Example running in directory, test-only mode with report output
![image](https://github.com/referefref/canarytokendetector/assets/56499429/4ee803e4-f820-4440-a116-706657da8152)

### Example running in nullify, verbose, directory mode (vdf)
![image](https://github.com/referefref/canarytokendetector/assets/56499429/957a316f-7b33-4f83-9d07-0677f3226732)

## Background and warranty
I wrote this script to augment a chapter on a book I'm writing about deception technologies, specifically around detection mechanisms for tokens. The detections are simple signature based detections which could easily be adjusted or randomised by Thinkst in future. This exists as a PoC, and no warranty of any is provided for the use (or misuse) of this application. Your actions are your own. You execute this at your own risk.
