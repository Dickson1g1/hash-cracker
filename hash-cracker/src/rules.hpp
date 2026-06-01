// rules.hpp
#pragma once
#include <string>
#include <vector>

// Each rule is a transformation applied to a candidate password.
// Rules are composable — a word can have multiple rules applied in sequence.
enum class Rule {
    NONE,           // original word unchanged
    CAPITALIZE,     // "password" → "Password"
    UPPERCASE,      // "password" → "PASSWORD"
    LEET,           // "password" → "p@55w0rd"
    APPEND_DIGITS,  // "password" → "password1", "password12", etc.
    REVERSE,        // "password" → "drowssap"
    TOGGLE_CASE,    // "password" → "pAsSwOrD"
    PREPEND_YEAR,   // "password" → "2024password"
    APPEND_BANG,    // "password" → "password!"
    DOUBLE,         // "password" → "passwordpassword"
};

// Apply all configured rules to a word and return the full candidate list.
// The original word is always included (NONE rule).
std::vector<std::string> apply_rules(const std::string& word,
                                      const std::vector<Rule>& rules);

// Returns the default rule set used when --rules flag is given
std::vector<Rule> default_rules();

// ---- rules.cpp ----
#include "rules.hpp"
#include <algorithm>
#include <cctype>

// Leet speak substitution table — common character replacements used in passwords
static std::string leet(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        switch (std::tolower(c)) {
            case 'a': c = '@'; break;
            case 'e': c = '3'; break;
            case 'i': c = '1'; break;
            case 'o': c = '0'; break;
            case 's': c = '5'; break;
            case 't': c = '7'; break;
        }
    }
    return out;
}

static std::string toggle_case(const std::string& s) {
    std::string out = s;
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = (i % 2 == 0)
            ? std::tolower(out[i])
            : std::toupper(out[i]);
    return out;
}

std::vector<std::string> apply_rules(const std::string& word,
                                      const std::vector<Rule>& rules) {
    std::vector<std::string> candidates;
    candidates.push_back(word);   // always include the original

    for (Rule r : rules) {
        switch (r) {
            case Rule::CAPITALIZE: {
                auto w = word;
                if (!w.empty()) w[0] = std::toupper(w[0]);
                candidates.push_back(w);
                break;
            }
            case Rule::UPPERCASE: {
                auto w = word;
                std::transform(w.begin(), w.end(), w.begin(), ::toupper);
                candidates.push_back(w);
                break;
            }
            case Rule::LEET:
                candidates.push_back(leet(word));
                break;
            case Rule::APPEND_DIGITS:
                // Append single digits 0-9 and common two-digit suffixes
                for (int d = 0; d <= 9; ++d)
                    candidates.push_back(word + std::to_string(d));
                for (int d : {12, 123, 1234, 99, 01})
                    candidates.push_back(word + std::to_string(d));
                break;
            case Rule::REVERSE: {
                auto w = word;
                std::reverse(w.begin(), w.end());
                candidates.push_back(w);
                break;
            }
            case Rule::TOGGLE_CASE:
                candidates.push_back(toggle_case(word));
                break;
            case Rule::PREPEND_YEAR:
                candidates.push_back("2023" + word);
                candidates.push_back("2024" + word);
                break;
            case Rule::APPEND_BANG:
                candidates.push_back(word + "!");
                candidates.push_back(word + "!!");
                break;
            case Rule::DOUBLE:
                candidates.push_back(word + word);
                break;
            default: break;
        }
    }
    return candidates;
}

std::vector<Rule> default_rules() {
    return {
        Rule::CAPITALIZE,
        Rule::UPPERCASE,
        Rule::LEET,
        Rule::APPEND_DIGITS,
        Rule::REVERSE,
        Rule::TOGGLE_CASE,
        Rule::APPEND_BANG,
    };
}
