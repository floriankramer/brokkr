# Brokkr
This is a tiny compiler project I'm working on for fun and to understand
compilation better. The goal is to have a very basic, vaguely c-like language
that is compiled directly to x86 byte code, and packaged in an elf file.
I'm purposefully not using a framework like llvm for this, as the goal is to
write these components myself in an attempt to get a very basic understanding
of how a compiler can be designed.

The compiler is written in rust. It can be built using `cargo build`, and run
using `cargo run`. It expects a single file as an input, and produces a
x86 64 bit elf file as it's output. The elf has no dependency, apart from a
reasonably up-to-date linux kernel for the syscalls.

### Neovim syntax highlighting
For basic neovim syntax highlighting, run the following
```
mkdir -p ~/.config/nvim/syntax
mkdir -p ~/.config/nvim/ftdetect
cp ./syntax.vim ~/.config/nvim/syntax/brkr.vim
cp ./filetype.vim ~/.config/nvim/ftdetect/brkr.vim
```
