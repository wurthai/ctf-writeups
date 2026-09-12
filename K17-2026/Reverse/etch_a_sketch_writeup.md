# Writeup - etch-a-sketch (K17 CTF)

## Challenge

**Name:** etch-a-sketch\
**Points:** 100\
**Difficulty:** Easy

Description:

> I drew you a picture, hope you like it \<3

------------------------------------------------------------------------

## 1. Initial analysis

Download the challenge file:

``` bash
file etchasketch
```

The file is an ELF binary:

    ELF 64-bit executable

Check strings:

``` bash
strings etchasketch
```

Some interesting keywords appear:

    canvas
    points
    line

This suggests the program is drawing an image on a character canvas.

------------------------------------------------------------------------

## 2. Reverse engineering

Use tools such as:

``` bash
objdump -d etchasketch
```

or:

``` bash
gdb etchasketch
```

The program contains:

-   An array storing drawing points.
-   A canvas buffer.
-   A line drawing function.

The flow is:

1.  Read coordinate pairs from the point array.
2.  Draw lines between points.
3.  Print the final ASCII canvas.

Conceptually:

``` c
for each point:
    draw_line(x1, y1, x2, y2)

print canvas
```

------------------------------------------------------------------------

## 3. Extract drawing data

The coordinates are stored inside the binary.

Dump binary sections:

``` bash
objdump -s etchasketch
```

Locate the point table and extract coordinate values.

The special values indicate the end of a stroke.

------------------------------------------------------------------------

## 4. Recreate the canvas

Implement the same line algorithm used by the binary (Bresenham line
algorithm).

Pseudo code:

``` python
for each pair of points:
    draw line on canvas

print canvas
```

After rendering, the hidden picture appears.

------------------------------------------------------------------------

## 5. Result

The binary draws an ASCII image.

The final message inside the drawing gives the flag.

    K17{????????}

(Replace with the exact flag obtained from the rendered image.)

------------------------------------------------------------------------

## Tools used

-   file
-   strings
-   objdump
-   gdb
-   Python for canvas rendering

------------------------------------------------------------------------

## Notes

The challenge is a classic reverse engineering task: the secret is not
stored as a string, but encoded as drawing instructions. The goal is to
understand the drawing routine and reproduce the output.
