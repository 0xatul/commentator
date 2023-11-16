# Commentator - MSDN annotations

## Overview

Commentator is a [IDA Pro](https://www.hex-rays.com/products/ida/) plugin for annotating decompiler output with the
function prototype of the winapi function just so its easier to focus.

## Installation

1. Copy `funcs.db` somewhere, and edit `commentator.py`'s `DB_PATH` accordingly
2. From your disassembler's python console, run the following command to find its plugin directory:
    - **IDA Pro**: `os.path.join(idaapi.get_user_idadir(), "plugins")`

3. Copy `commentator.py` to the listed directory
4. Restart IDA.

This plugin assumes you have python3

## Usage

Put the cursor to the function call which you want to annotation for and press `Ctrl-Alt-S`, every call for that
function in that idb is annotated


## Thanks