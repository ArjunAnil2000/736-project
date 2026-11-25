Hello. You're reading this because you're probably facing challenges with page counts and space. Here are things to do to help:

1. Immediately after `\usepackage{enumitem}`, add in:
```
\setlist{
    nosep,
    leftmargin=*,
    labelsep=0.3em
}

\setlist[enumerate,1]{
    label=(\arabic*)
}
```
2. Before `\begin{document}`
```
% Compact floats
\setlength{\floatsep}{6pt plus 2pt minus 1pt}
\setlength{\textfloatsep}{7pt plus 2pt minus 2pt}
\setlength{\intextsep}{6pt plus 2pt minus 1pt}
\setlength{\dblfloatsep}{6pt plus 2pt minus 1pt}
\setlength{\dbltextfloatsep}{7pt plus 2pt minus 2pt}

% Compact captions
\captionsetup{skip=3pt}
```
3. Before `\begin{document}`
```
% Compact tables
\setlength{\tabcolsep}{4pt}
\renewcommand{\arraystretch}{0.95}
```
4. Tables should follow the format:
```
\begin{tabular}{@{}lccc@{}}
```
The `@{}` specifically removing padding on the outer edges.
5. Add before terminating paragraph break `\looseness=-1\par` when the paragraph has like 2 words on the last line.
6. Use `\settopmatter{authorsperrow=3}` to