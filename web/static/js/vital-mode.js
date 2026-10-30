// CodeMirror mode for Multilingual VITAL Programming Language
// Supports all 6 languages: English, Hindi, Telugu, Bengali, Marathi, Nepali

(function (mod) {
  if (typeof exports == "object" && typeof module == "object")
    mod(require("codemirror"));
  else if (typeof define == "function" && define.amd)
    define(["codemirror"], mod);
  else
    mod(CodeMirror);
})(function (CodeMirror) {
  "use strict";

  CodeMirror.defineMode("vital", function (config, parserConfig) {

    // All Multilingual VITAL Keywords
    var keywords = [
      // Control flow & structure
      "begin", "start", "end", "finish", "function", "def", "return",
      "let", "make", "variable", "set", "assign", "const", "fixed",
      "if", "check", "agar", "elif", "else_if", "else", "otherwise",
      "for", "repeat", "while", "jabtak", "break", "stop_loop", "continue", "skip",
      "print", "show", "display", "input", "ask", "read",
      "and", "or", "not",

      // Hindi
      "शुरू", "समाप्त", "कार्य", "लौटाओ", "वापस",
      "मान_दो", "मानो", "है", "नियत",
      "अगर", "यदि", "या_अगर", "अन्यथा", "वरना", "नहीं_तो",
      "के_लिए", "जबतक", "रुको", "जारी",
      "छापो", "लिखो", "दिखाओ", "पूछो",
      "और", "तथा", "या", "अथवा", "नहीं",

      // Telugu
      "ప్రారంభించు", "మొదలు", "ముగించు", "ఆపు", "ఫంక్షన్", "పని", "తిరిగి_ఇవ్వు", "తిరిగి",
      "అనుకో", "తీసుకో", "అయి", "ఉండు", "స్థిరం",
      "ఒకవేళ", "అయితే", "లేదా_అయితే", "లేదా_ఒకవేళ", "కాకపోతే", "లేదా",
      "కొరకు", "ఉన్నంతవరకు", "అంతవరకు", "విచ్ఛిన్నం", "కొనసాగించు",
      "ముద్రించు", "చూపించు", "రాయి", "అడుగు", "చదువు",
      "మరియు", "కాదు", "వద్దు",

      // Bengali
      "শুরু", "শেষ", "ফাংশন", "ফেরত",
      "ধরো", "মানো", "হলো", "আছে", "স্থির",
      "যদি", "নাহলে_যদি", "নাহলে", "নতুবা",
      "জন্য", "যতক্ষণ", "থামো", "চলো",
      "ছাপাও", "দেখাও", "ইনপুট", "জিজ্ঞাসা",
      "এবং", "অথবা", "না", "নয়",

      // Marathi
      "सुरू", "संपले", "कार्य_करा", "परत_करा",
      "घ्या", "ठरवा", "आहे", "ठेवा", "स्थिर",
      "जर", "नाहीतर_जर", "नाहीतर",
      "साठी", "जोपर्यंत", "बंद_करा", "पुढे_चला",
      "लिहा", "दाखवा", "विचारा",
      "आणि", "किंवा", "नाही",

      // Nepali
      "सुरु", "समाप्त_गर", "कार्य_गर", "फिर्ता",
      "मान", "राख", "हो", "राख_गर", "स्थिर_गर",
      "यदि_हो", "नत्र_यदि", "नत्र",
      "को_लागि", "जबसम्म", "रोक", "जारी_राख",
      "छाप", "देखाउ", "इनपुट", "सोध",
      "र", "वा", "होइन"
    ];

    // Multilingual Operators
    var wordOperators = [
      "add", "subtract", "multiply", "divide", "equal_to", "greater_than", "less_than", "greater_equal", "less_equal", "not_equal",
      // Hindi
      "जोड़", "घटाओ", "गुणा", "भाग", "के_बराबर", "से_बड़ा", "से_छोटा", "से_बड़ा_या_बराबर", "से_छोटा_या_बराबर", "बराबर_नहीं",
      // Telugu
      "కూడిక", "కలుపు", "తీసివేత", "తీసివేయి", "గుణకారం", "హెచ్చవేయి", "భాగహారం", "భాగించు", "సమానం", "కంటే_పెద్దది", "కంటే_చిన్నది", "కంటే_పెద్దది_లేదా_సమానం", "కంటే_చిన్నది_లేదా_సమానం", "సమానం_కాదు",
      // Bengali
      "যোগ", "জমা", "বিয়োগ", "বাদ", "গুণ", "ভাগ", "সমান", "বড়", "ছোট", "বড়_বা_সমান", "ছোট_বা_সমান", "সমান_না",
      // Marathi
      "जोडा", "वजा", "गुणाकार", "भागाकार", "बरोबर", "पेक्षा_मोठे", "पेक्षा_लहान", "मोठे_किंवा_बरोबर", "लहान_किंवा_बरोबर", "बरोबर_नाही",
      // Nepali
      "जोड", "वजाब", "गुणन", "भाग_गर", "बराबर", "भन्दा_ठूलो", "भन्दा_सानो", "ठूलो_वा_बराबर", "सानो_वा_बराबर", "बराबर_छैन"
    ];

    var commentPrefixes = [
      "टिप्पणी_गर", "टिप्पणी", "వ్యాఖ్య", "মন্তব্য", "टीप", "//", "#"
    ];

    var keywordSet = {};
    keywords.forEach(function (kw) { keywordSet[kw] = true; });

    var opSet = {};
    wordOperators.forEach(function (op) { opSet[op] = true; });

    return {
      startState: function () {
        return {
          inString: false,
          stringQuote: null
        };
      },
      token: function (stream, state) {
        // Handle whitespace
        if (stream.eatSpace()) return null;

        // Handle string literals
        if (state.inString) {
          while (!stream.eol()) {
            var ch = stream.next();
            if (ch === "\\") {
              stream.next();
            } else if (ch === state.stringQuote) {
              state.inString = false;
              state.stringQuote = null;
              break;
            }
          }
          return "string";
        }

        // Start of string
        var ch = stream.peek();
        if (ch === '"' || ch === "'") {
          state.inString = true;
          state.stringQuote = stream.next();
          return "string";
        }

        // Check for multilingual comments
        for (var i = 0; i < commentPrefixes.length; i++) {
          var prefix = commentPrefixes[i];
          if (stream.match(prefix)) {
            stream.skipToEnd();
            return "comment";
          }
        }

        // Numbers
        if (stream.match(/^[0-9]+(\.[0-9]+)?/)) {
          return "number";
        }

        // Punctuation & symbolic operators
        if (stream.match(/^(==|!=|<=|>=|[+\-*/%=<>!{}();:,])/)) {
          return "operator";
        }

        // Word tokens (identifiers, keywords, word-operators)
        // Unicode letter classes for Indic scripts
        var wordMatch = stream.match(/^[a-zA-Z0-9_\u0900-\u097F\u0980-\u09FF\u0C00-\u0C7F]+/);
        if (wordMatch) {
          var word = wordMatch[0];
          if (keywordSet.hasOwnProperty(word)) {
            return "keyword";
          }
          if (opSet.hasOwnProperty(word)) {
            return "operator";
          }
          if (word === "true" || word === "false" || word === "null" || word === "None") {
            return "atom";
          }
          return "variable";
        }

        // Advance single character fallback
        stream.next();
        return null;
      }
    };
  });

  CodeMirror.defineMIME("text/x-vital", "vital");
});
