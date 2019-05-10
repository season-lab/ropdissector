# ROPDissector

ROPDissector is a system for performing static analysis of ROP payloads such as exploits and self-contained ROP programs. It embodies the ideas from the paper *Static analysis of ROP code* (EuroSec '19).

The present branch contains the code used in the paper. We maintain [here](https://github.com/season-lab/rop-collection) a collection of ROP exploits and programs that we used for the EuroSec '19 evaluation and that might be of interest for a broader audience.

# Overview

ROPDissector is currently made of two components:
* an emulation engine with control-flow reconstruction and gadget analysis capabilities
* gadget guessing algorithms to identify plausible candidate images by looking at chain addresses only

ROPDissector mainly builds on Capstone and Unicorn. As detailed in the paper, it has been tested against a [collection of ROP payloads](https://github.com/season-lab/rop-collection) for Windows with heterogeneous features that we assembled over time.

# Emulation engine

In the following we describe how to set up the emulation engine and run it over a demo payload. The implementation has been tested on Windows and currently targets 32-bit Windows payloads (but Linux and 64-bit are in our agenda!).

## Installation

Using virtualenv is advised. You can retrieve the Python dependencies with:
```bash 
$ pip install -r engine/requirements.txt
```
Then get a compiled build of [graphviz](https://graphviz.gitlab.io/download/) and add its executables to the PATH environment variable of your system.

We use BARF for providing semantic annotations for gadgets. To retrieve it:

```bash
$ git clone https://github.com/programa-stic/barf-project
$ cd barf-project
$ python setup.py install
```

If you are using virtualenv, copy the barf/ folder into the site-packages/ folder of your Python environment:
```bash
$ cp -R barf path_to_virtualenv/lib/site-packages/
```

BARF requires the Z3 SMT solver as a dependency. You can find it [here](https://github.com/Z3Prover/z3).

## Usage

To analyze a ROP chain you need to prepare a JSON file that specifies the PE images to be used as gadget sources, the raw bytes (as a list of hex strings representing 4-byte tuples) to be placed on stack, the first gadget in the chain, and if the payload is ROP-only or it returns to shellcode. We provide a number of demo examples in the folder `demo-payloads/` and more in the ROP collection repository. To begin the analysis:

```bash
$ python engine/main.py demo-payloads/json/bubblesort.json
```

Upon execution of a payload ROPDissector will display information on memory reads and writes (including unknown regions that are mapped on the fly in the emulator), identified calls to library functions and syscalls, information on branching locations and explored paths, and gadgets found in the chain with semantic annotations provided by BARF. ROPDissector can be configured to print also the contents of general-purpose registers and the stack at every executed gadget: this behavior is controlled by variable `VERBOSE_LOGGING` in `engine/emulator.py`. 

Intended for payloads with multiple control-flow paths, the `output/` folder will contain five items: two GraphViz files for the ROP CFG (with and without basic block labels made of associated gadgets), a GraphViz file for the classic EIP-based CFG, and two files containing <ESP, EIP> and EIP traces for the distinct paths explored in the code.



# Gadget guessing

The gadget guessing component uses pyvex, ropper, and ROPgadget as Python dependencies. To install them:
```bash 
$ pip install -r guessing/requirements.txt
```

Another dependecy is [Nucleus](https://bitbucket.org/vusec/nucleus/src/master/). Currently you should be using a Linux machine to parse PE files for function offsets.

*Please be patient for a little longer, we will complete this part soon :-)*

# Authors
* Andrea Salvati ([@AnSlvt](https://github.com/AnSlvt))
* Daniele Cono D'Elia ([@dcdelia](https://github.com/dcdelia))
* Luca Borzacchiello ([@borzacchiello](https://github.com/borzacchiello))

If you are using ROPDissector or our collection of ROP payloads in your research, we would be grateful if you may consider citing us using the following entry:
``` tex
@inproceedings{ROPSc-EuroSec19,
 author = {D'Elia, Daniele Cono and Coppa, Emilio and Salvati, Andrea and Demetrescu, Camil},
 title = {Static Analysis of ROP Code},
 booktitle = {Proceedings of the 12th European Workshop on Systems Security},
 series = {EuroSec '19},
 year = {2019},
 isbn = {978-1-4503-6274-0},
 location = {Dresden, Germany},
 pages = {2:1--2:6},
 articleno = {2},
 numpages = {6},
 url = {http://doi.acm.org/10.1145/3301417.3312494},
 doi = {10.1145/3301417.3312494},
 publisher = {ACM},
 address = {New York, NY, USA},
}
```

