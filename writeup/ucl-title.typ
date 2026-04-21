// UCL thesis title page
// Mirrors the standard UCL LaTeX \maketitle template:
//   logo → large title → subtitle (upper-centre block)
//   date / author / degree / supervisor (lower-centre block)
//   disclaimer footnote at bottom (mirrors \thanks{})
//
// Usage:
//   #ucl-title-page(
//     logo-path:    "ucl_logo.png",   // place file next to main.typ
//     title:        "Your Title",
//     subtitle:     "Optional Subtitle",   // pass none to omit
//     date:         "Day Month Year",
//     author:       "Your Name",
//     degree:       "MEng/MSc Computer Science",
//     supervisor:   "Prof. Supervisor",
//     distribution: "open",           // "open" or "restricted"
//   )

#let ucl-title-page(
  logo-path: "ucl_logo.png",
  title: "Project Title",
  subtitle: none,
  date: "Day Month Year",
  author: "Your Name",
  degree: "Name of Your Degree",
  supervisor: "Supervisor's Name",
  distribution: "open",
) = {
  // ── Main centred block (logo + title + subtitle + author info) ─────────────
  // align(center + horizon) mirrors LaTeX \maketitle vertical centering.
  align(center + horizon)[
    #image(logo-path, height: 3.5cm)

    #v(2em)

    #text(size: 26pt, weight: "bold")[#title]

    #if subtitle != none {
      v(0.8em)
      text(size: 14pt, style: "italic")[#subtitle]
    }

    #v(3em)

    #text(size: 13pt)[#author]

    #v(2.5em)

    #text(size: 11pt)[#degree]

    #v(1.2em)

    #text(size: 12pt)[Submission date: #date]

    #v(0.6em)

    #text(size: 11pt)[Supervised by: #supervisor]
  ]

  // ── Disclaimer footnote (mirrors \thanks{}) ────────────────────────────────
  // place(bottom) anchors to the bottom of the page body, outside the flow,
  // exactly like a LaTeX \thanks{} footnote.
  place(bottom)[
    #line(length: 100%, stroke: 0.5pt + black)
    #v(0.6em)
    #text(size: 8.5pt)[
      #set par(justify: true)
      *Disclaimer:* This report is submitted as part requirement for the
      #degree at UCL. It is substantially the result of my own work except
      where explicitly indicated in the text.

      #if distribution == "open" [
        _The report may be freely copied and distributed provided the source
        is explicitly acknowledged._
      ] else [
        _The report will be distributed to the internal and external examiners,
        but thereafter may not be copied or distributed except with permission
        from the author._
      ]
    ]
    #v(1em)
  ]
}
