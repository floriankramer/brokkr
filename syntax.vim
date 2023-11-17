" Vim syntax file
" Language: Brokkr 
" Maintainer: Florian Kramer 
" Latest Revision: 17 Novembver 2023

if exists("b:current_syntax")
  finish
endif


" Types
syn keyword Type void uint64 double uint8

" Keywords
syn keyword Keyword return global
syn keyword Conditional if while

" Literals
syn region String start=/"/ skip=/\\"/ end=/"/
syn match Float "[0-9]+\.[0-9]+" 
syn match Number "[0-9]+" 

" Comments
syn region Comment start="//" end="\n"


" Bind this to highlighting info
let b:current_syntax = "brkr"
hi def link Type Type
hi def link Keyword Keyword
hi def link Conditional Conditional
hi def link String String
hi def link Float Float
hi def link Number Number
hi def link Comment Comment
