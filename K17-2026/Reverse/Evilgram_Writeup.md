# Writeup - Evilgram (K17 CTF)

## Challenge Information

-   **Name:** Evilgram
-   **Category:** Reverse Engineering / Cryptography
-   **Difficulty:** Medium
-   **Points:** 111

## Description

Evilgram is a social network used by villains. A suspect account was
compromised, but no direct evidence of wrongdoing could be found. The
account contained strange changing messages sent to criminals. The
objective is to recover the hidden message and obtain the flag.

Connection:

    https://evilgram.unswsecsoc.workers.dev

------------------------------------------------------------------------

# 1. Initial Analysis

The challenge provides an Evilgram webpage containing conversations and
animated messages.

Looking at the page source reveals that the strange messages are not
normal text. They are generated using a visualization system.

Important functions found:

``` python
message = open(MESSAGE_FILE, 'r').read()

ruleset = encode_msg_to_ruleset(message)

hist = generateHist(ruleset, history_size, map_size, seed)
```

The hidden message is converted into a ruleset and then used to generate
a cellular automaton.

------------------------------------------------------------------------

# 2. Extracting Animation Data

The webpage uses Plotly to display a 3D animation.

Inside the HTML source:

``` javascript
Plotly.addFrames(...)
```

Each animation frame contains voxel coordinates:

``` javascript
x[]
y[]
z[]
```

The animation represents a 3D grid state.

By extracting all frames, we obtain:

    frame[0]
    frame[1]
    ...
    frame[127]

Each frame is one state of the cellular automaton.

------------------------------------------------------------------------

# 3. Understanding the Cellular Automaton

The generation algorithm works like:

``` python
blockState = calcBlockState(map,...)

nextBlockState = rules[blockState]

setBlockState(map,..., nextBlockState)
```

Meaning:

    Current state  ->  Rule lookup  ->  Next state

The unknown part is the ruleset.

Because both the current frame and the next frame are available, we can
recover the rules.

For every transition:

    frame[n] -> frame[n+1]

we calculate:

    rules[input_state] = output_state

After processing all 127 transitions, the complete ruleset is
reconstructed.

------------------------------------------------------------------------

# 4. Reversing encode_msg_to_ruleset()

The recovered ruleset is generated from the original message using a
permutation encoding.

The encoding uses factorial number system:

``` python
for skip_count in factoradic:
    selected_number = l.pop(skip_count)
```

This means the message bytes were converted into a permutation.

To reverse:

1.  Recover the permutation from the cellular automaton rules.
2.  Convert permutation back into factoradic representation.
3.  Convert the resulting integer into bytes.
4.  Decode UTF-8 text.

------------------------------------------------------------------------

# 5. Recovered Message

The decoded message:

    please i NEED the kfc recipe ASAP my local kfc closed down and I NEED MY CHICKEN

The hidden flag is:

    K17{y0u_Th0ug5t_W3_w3Re_Ev1l_bUt_re4llY_we_are_JuSt_m4ss1ve_cH1cken_l0vers_w1th_a_huge_Hung3r_anD_n0th1ng_cAn_sT4nD_1n_OuR_way!!}

------------------------------------------------------------------------

# Final Flag

    K17{y0u_Th0ug5t_W3_w3Re_Ev1l_bUt_re4llY_we_are_JuSt_m4ss1ve_cH1cken_l0vers_w1th_a_huge_Hung3r_anD_n0th1ng_cAn_sT4nD_1n_OuR_way!!}

------------------------------------------------------------------------

# Lessons Learned

-   Always inspect JavaScript/HTML source in web CTF challenges.
-   Plotly animations can contain hidden data.
-   Cellular automata can leak transition rules if enough states are
    visible.
-   Factorial number system is often used to encode permutations.
-   Reverse the generation pipeline instead of trying to guess the
    message.
