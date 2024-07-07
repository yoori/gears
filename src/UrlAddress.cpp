#include <cassert>

#include <gears/StringManip.hpp>
#include <gears/UTF8Category.hpp>
//#include <String/UTF8AllProperties.hpp>
#include <gears/UnicodeNormalizer.hpp>
#include <gears/Function.hpp>
#include <gears/OutputMemoryStream.hpp>

#include <gears/UrlAddress.hpp>

namespace Gears
{
  namespace
  {
    using namespace HTTP;

    const Ascii::Caseless WWW("www.");

    // The following are taken from RFC 3986
    // Appendix A
    const Ascii::CharCategory UNRESERVED(
      Ascii::ALPHA_NUM,
      Ascii::CharCategory("-._~"));
    const Ascii::CharCategory SUB_DELIMS("!$&'()*+,;=");
    const Ascii::CharCategory PCHAR(
      UNRESERVED,
      SUB_DELIMS,
      Ascii::CharCategory(":@"));

    // These are not RFC-compliant symbols but apache works with them
    const Ascii::CharCategory NON_COMPLIANT("{}|^~[]`");

    // Url splitting
    const Ascii::CharCategory
      URL_PARSER_SCHEME_END(":/?#");
    typedef const Ascii::Char3Category<'/', '?', '#'>
      UrlParserAuthorityEnd;
    UrlParserAuthorityEnd URL_PARSER_AUTORITY_END{};
    typedef const Ascii::Char2Category<'?', '#'>
      UrlParserPathEnd;
    UrlParserPathEnd URL_PARSER_PATH_END{};
    typedef const Ascii::Char1Category<'#'>
      UrlParserQueryEnd;
    UrlParserQueryEnd URL_PARSER_QUERY_END{};

    // Part 3.1
    const Ascii::CharCategory& SCHEME_FIRST(
      Ascii::ALPHA);
    const Ascii::CharCategory SCHEME_NOT_FIRST(
      Ascii::ALPHA_NUM,
      Ascii::CharCategory("-+."));

    // Part 3.2.1
    const Ascii::CharCategory USER_INFO(
      UNRESERVED,
      SUB_DELIMS,
      Ascii::CharCategory(":"));

    // Part 3.2.2 is too wide for DNS, using special per-label checks
    const Ascii::CharCategory HOST(
      UNRESERVED,
      SUB_DELIMS);

    // Part 3.2.3
    const Ascii::CharCategory& PORT(
      Ascii::NUMBER);

    // Part 3.3 (Simplified)
    const Ascii::CharCategory PATH(
      NON_COMPLIANT,
      PCHAR,
      Ascii::CharCategory("/"));

    // Part 3.4
    const Ascii::CharCategory QUERY(
      NON_COMPLIANT,
      PCHAR,
      Ascii::CharCategory("/?"));

    // Part 3.5
    const Ascii::CharCategory FRAGMENT(
      NON_COMPLIANT,
      PCHAR,
      Ascii::CharCategory("/?"));


    const char SCHEME_SUFFIX = ':';
    const std::size_t SCHEME_SUFFIX_SIZE = 1;
    const char AUTHORITY_PREFIX[] = "//";
    const std::size_t AUTHORITY_PREFIX_SIZE = 2;
    const char USERINFO_SEPARATOR = '@';
    const std::size_t USERINFO_SEPARATOR_SIZE = 1;
    const char PORT_SEPARATOR = ':';
    const std::size_t PORT_SEPARATOR_SIZE = 1;
    const char QUERY_SEPARATOR = '?';
    const std::size_t QUERY_SEPARATOR_SIZE = 1;
    const char FRAGMENT_SEPARATOR = '#';
    const std::size_t FRAGMENT_SEPARATOR_SIZE = 1;
    // all address separators size, separators = "://@:?#"
    const std::size_t ALL_SEPS_SIZE = 7;

    const unsigned short DEFAULT_HTTP_PORT = 80;
    const unsigned short DEFAULT_HTTPS_PORT = 443;
    const SubString DEFAULT_PATH("/", 1);
    const char PATH_SEPARATOR = '/';
    const std::size_t PATH_SEPARATOR_SIZE = 1;
    const SubString SCHEME_AUTHORITY_MEDIATOR("://", 3);

    // RFC 1034
    const size_t MAX_HOSTNAME_LABEL_SIZE = 63;
    const size_t MAX_HOSTNAME_SIZE = 255;

    const char LABEL_SEPARATOR = '.';
    typedef const Ascii::Char1Category<LABEL_SEPARATOR>
      LabelSeparatorCategory;

    // 3.5 of RFC1034 and 2.1 of RFC1123.
    // Also non-standard underscore is included.
    const Ascii::CharCategory LABEL_FIRST_LAST(
      Ascii::ALPHA_NUM,
      Ascii::CharCategory("_"));
    const Ascii::CharCategory LABEL_MIDDLE(
      Ascii::ALPHA_NUM,
      Ascii::CharCategory("-_"));


    inline
    bool
    is_valid_chars(const SubString& str,
      const Ascii::CharCategory& category) throw ()
    {
      const char* const END = str.end();
      return category.find_nonowned(str.begin(), END) == END;
    }

    inline
    const char*
    find_invalid(const char* str, const char* end,
      const Ascii::CharCategory& category) throw ()
    {
      while ((str = category.find_nonowned(str, end)) && str != end)
      {
        if (*str != '%')
        {
          return str;
        }
        if (end - str < 3 ||
          !Ascii::HEX_NUMBER(str[1]) ||
          !Ascii::HEX_NUMBER(str[2]))
        {
          return str;
        }
        str += 3;
      }
      return end;
    }

    bool
    is_valid_encoded(const SubString& encoded_str,
      const Ascii::CharCategory& category) throw ()
    {
      const char* const END = encoded_str.end();
      return find_invalid(encoded_str.begin(), END, category) == END;
    }

    /**
     * Create an error message.
     */
    bool
    make_invalid(std::string& error, const char* type,
      const SubString& url)
    {
      error = std::string("invalid ") + type + " '";
      url.append_to(error);
      error.push_back('\'');
      return false;
    }

    bool
    check_http_url_components(const SubString& url,
      const SubString& scheme, const SubString& host,
      std::string& error, bool strict) /*throw (eh::Exception)*/
    {
      if (scheme != HTTP_SCHEME && scheme != HTTPS_SCHEME &&
        (strict || !scheme.empty()))
      {
        return make_invalid(error, "unexpected protocol in url", url);
      }

      if (host.empty())
      {
        return make_invalid(error, "empty server name in url", url);
      }

      return true;
    }

    bool
    http_url_needs_prefix(const SubString& scheme,
      const SubString& host) /*throw (eh::Exception)*/
    {
      return host.empty() && scheme != HTTP_SCHEME && scheme != HTTPS_SCHEME;
    }

    void
    http_add_scheme(std::string& fixed_url, const SubString& url)
      /*throw (eh::Exception)*/
    {
      fixed_url.reserve(HTTP_SCHEME.str.size() +
        SCHEME_AUTHORITY_MEDIATOR.size() + url.size());
      HTTP_SCHEME.str.append_to(fixed_url);
      SCHEME_AUTHORITY_MEDIATOR.append_to(fixed_url);
      url.append_to(fixed_url);
    }

    bool
    http_fix_part(const SubString& part,
      const Ascii::CharCategory& checker,
      std::string& new_part) /*throw (eh::Exception)*/
    {
      const char* const END = part.end();
      const char* str = find_invalid(part.begin(), END,
        checker);
      if (str == END)
      {
        return false;
      }
      new_part.reserve(part.length() * 3);
      new_part.append(part.begin(), str);
      do
      {
        const char CH = *str;
        const char buf[] = { '%',
          Ascii::HEX_DIGITS[(CH >> 4) & 0x0F],
          Ascii::HEX_DIGITS[CH & 0x0F] };
        new_part.append(buf, sizeof(buf));
        const char* const OLD = str + 1;
        str = find_invalid(OLD, END, QUERY);
        new_part.append(OLD, str);
      }
      while (str != END);
      return true;
    }

    const Ascii::Caseless IDNA_PREFIX("xn--");
    const char IDNA_DELIMITER = '-';
    const Ascii::CharCategory IDNA_ALLOWED(
      Ascii::ALPHA_NUM,
      Ascii::CharCategory("-"));

    struct PartCheckInfo
    {
      PartCheckInfo(SubString& part,
        const Ascii::CharCategory& checker)
        /*throw (eh::Exception)*/;

      SubString& part;
      const Ascii::CharCategory& CHECKER;
      std::string new_part;
    };

    PartCheckInfo::PartCheckInfo(SubString& part,
      const Ascii::CharCategory& checker)
      /*throw (eh::Exception)*/
      : part(part), CHECKER(checker)
    {
    }

    void
    unmime(const SubString& str,
      const Ascii::CharCategory& valid,
      std::string& result)
    {
      result.clear();
      result.reserve(str.length());
      for (auto itor(str.begin()); itor != str.end(); ++itor)
      {
        if (*itor == '%')
        {
          ++itor;
          assert(itor != str.end());
          assert(Ascii::HEX_NUMBER(*itor));
          assert(str.end() - itor >= 2);
          ++itor;
          char ch = Ascii::hex_to_char(itor[-1], *itor);
          if (valid(ch))
          {
            result.push_back(Ascii::to_lower(ch));
          }
          else
          {
            char buf[3] = { '%',
              Ascii::to_lower(itor[-1]),
              Ascii::to_lower(*itor) };
            result.append(buf, 3);
          }
        }
        else
        {
          result.push_back(Ascii::to_lower(*itor));
        }
      }
    }

    void
    unmime_all(const SubString& src, std::string& dst)
    {
      dst.clear();
      dst.reserve(src.size());
      for (auto it = src.begin(); it != src.end(); it++)
      {
        if (*it == '%' && src.end() - it >= 3 &&
          Ascii::HEX_NUMBER(it[1]) &&
          Ascii::HEX_NUMBER(it[2]))
        {
          dst.push_back(Ascii::hex_to_char(it[1], it[2]));
          it += 2;
        }
        else
        {
          dst.push_back(*it);
        }
      }
    }


    class IDNA0 : private Uncopyable
    {
    public:
      explicit
      IDNA0(std::string& ascii) throw ();

      ~IDNA0() throw ();

      void
      append(const SubString& label);

    private:
      std::string& ascii_;
    };

    IDNA0::IDNA0(std::string& ascii) throw ()
      : ascii_(ascii)
    {
    }

    IDNA0::~IDNA0() throw ()
    {
      Ascii::to_lower(ascii_);
    }

    void
    IDNA0::append(const SubString& label)
    {
      if (IDNA_PREFIX.start(label))
      {
        throw HTTP::BrowserAddress::IDNAError(
          "Possibly IDNA label");
      }
    }

    class IDNA2008 : private Uncopyable
    {
    public:
      IDNA2008(std::string& ascii, std::string& unicode) throw ();

      void
      append(const WSubString& label);

    private:
      bool
      decode_(const WSubString& lab, std::string& alabel,
        std::wstring& decoded, WSubString& wlab, bool& unicode);
      bool
      encode_(const WSubString& wlabel, bool unicode);

      std::string& ascii_;
      std::string& unicode_;
    };

    IDNA2008::IDNA2008(std::string& ascii, std::string& unicode) throw ()
      : ascii_(ascii), unicode_(unicode)
    {
    }

    bool
    IDNA2008::decode_(const WSubString& lab, std::string& alabel,
      std::wstring& decoded, WSubString& wlab, bool& unicode)
    {
      unicode = false;
      alabel.reserve(lab.size() + 1);
      for (WSubString::SizeType i = 0; i < lab.size(); i++)
      {
        if (lab[i] >= 0x80)
        {
          unicode = true;
          break;
        }
        alabel.push_back(static_cast<char>(lab[i]));
      }

      if (unicode)
      {
        wlab = lab;
      }
      else
      {
        if (!is_valid_chars(alabel, HOST))
        {
          Gears::ErrorStream ostr;
          ostr << "Invalid input sequence in label '" << alabel << "'";
          throw BrowserAddress::IDNAError(ostr.str());
        }

        if (!IDNA_PREFIX.start(alabel) ||
          alabel.size() == IDNA_PREFIX.str.size() ||
          *IDNA_ALLOWED.find_nonowned(alabel.c_str()) ||
          !StringManip::punycode_decode(
            SubString(alabel).substr(IDNA_PREFIX.str.size()),
              decoded))
        {
          return true;
        }

        std::wstring normalized;
        if (!lower_and_normalize(decoded, normalized, false) ||
          normalized.empty())
        {
          return true;
        }

        decoded = std::move(normalized);
        wlab = decoded;
      }

      return false;
    }

    bool
    IDNA2008::encode_(const WSubString& wlabel, bool unicode)
    {
      if (wlabel[0] == IDNA_DELIMITER ||
        wlabel[wlabel.size() - 1] == IDNA_DELIMITER)
      {
        if (unicode)
        {
          throw BrowserAddress::IDNAError("extra hyphens");
        }
        return false;
      }

      std::string encoded;
      if (!StringManip::punycode_encode(wlabel, encoded))
      {
        if (unicode)
        {
          throw BrowserAddress::IDNAError("punycode failure");
        }
      }

      if (*IDNA_ALLOWED.find_nonowned(encoded.c_str()))
      {
        if (unicode)
        {
          throw BrowserAddress::IDNAError(
            "Invalid symbols in the encoded label");
        }
        return false;
      }

      if (encoded[encoded.size() - 1] == IDNA_DELIMITER)
      {
        if (unicode)
        {
          throw BrowserAddress::IDNAError(
            "Extra hyphens in the encoded label");
        }
        return false;
      }

      for (auto itor(wlabel.begin()); itor != wlabel.end(); ++itor)
      {
        char buf[16];
        unsigned long octets_count;
        if (!UTF8Handler::ulong_to_utf8_char(*itor, buf,
          octets_count))
        {
          if (unicode)
          {
            throw BrowserAddress::IDNAError("Invalid input sequence");
          }
          return false;
        }
        unicode_.append(buf, octets_count);
      }
      unicode_.push_back(LABEL_SEPARATOR);

      IDNA_PREFIX.str.append_to(ascii_);
      ascii_.append(encoded);
      ascii_.push_back(LABEL_SEPARATOR);

      return true;
    }

    void
    IDNA2008::append(const WSubString& label)
    {
      std::string alabel;
      std::wstring decoded;
      WSubString wlabel;
      bool unicode;

      do
      {
        if (decode_(label, alabel, decoded, wlabel, unicode))
        {
          break;
        }

        bool has_nonascii = false;
        for (auto itor(wlabel.begin()); itor != wlabel.end(); ++itor)
        {
          if (*itor >= 0x80)
          {
            has_nonascii = true;
            break;
          }
        }

        if (has_nonascii)
        {
          if (!encode_(wlabel, unicode))
          {
            break;
          }
        }
        else
        {
          std::string adecoded;
          adecoded.reserve(wlabel.size() + 1);
          for (WSubString::SizeType i = 0; i < wlabel.size(); i++)
          {
            adecoded.push_back(static_cast<char>(wlabel[i]));
          }
          if (!is_valid_chars(adecoded, HOST))
          {
            alabel.push_back(LABEL_SEPARATOR);
            ascii_.append(alabel);
            adecoded.push_back(LABEL_SEPARATOR);
            unicode_.append(adecoded);
          }
          else
          {
            adecoded.push_back(LABEL_SEPARATOR);
            ascii_.append(adecoded);
            unicode_.append(adecoded);
          }
        }

        return;
      }
      while (false);

      alabel.push_back(LABEL_SEPARATOR);
      ascii_.append(alabel);
      unicode_.append(alabel);
    }


    std::string
    convert_label(const WSubString& label)
    {
      std::string utf8;
      StringManip::wchar_to_utf8(label, utf8);
      return utf8;
    }

    const SubString&
    convert_label(const SubString& label)
    {
      return label;
    }

    template <typename SubStringT, typename Dest>
    void
    idna_label_convert(const SubString& host,
      const SubStringT& normalized, Dest&& dst)
      /*throw (eh::Exception, BrowserAddress::IDNAError)*/
    {
      typename SubStringT::SizeType last = 0, pos;
      SubStringT label;
      for (;;)
      {
        if (last >= normalized.size())
        {
          break;
        }
        pos = normalized.find(LABEL_SEPARATOR, last);
        if (pos == SubStringT::NPOS)
        {
          pos = normalized.size();
        }
        label = normalized.substr(last, pos - last);
        last = pos + 1;

        if (label.empty())
        {
          Gears::ErrorStream ostr;
          ostr << FNS << "Empty label in '" << host << "'";
          throw BrowserAddress::IDNAError(ostr.str());
        }

        if (label.size() > MAX_HOSTNAME_LABEL_SIZE)
        {
          Gears::ErrorStream ostr;
          ostr << FNS << "Label '" << convert_label(label) <<
            "' in '" << host << "' is too large";
          throw BrowserAddress::IDNAError(ostr.str());
        }

        try
        {
          dst.append(label);
        }
        catch (const BrowserAddress::IDNAError& ex)
        {
          Gears::ErrorStream ostr;
          ostr << FNS << "Problem with label '" <<
            convert_label(label) << "' in '" << host <<
            "': " << ex.what();
          throw BrowserAddress::IDNAError(ostr.str());
        }
      }
    }

    void
    idna_normalize_host(const SubString& host, std::string& ascii,
      std::string& unicode)
    {
      if (host.empty())
      {
        throw BrowserAddress::IDNAError("Host name is empty");
      }

      if (host.size() >= MAX_HOSTNAME_SIZE)
      {
        Gears::ErrorStream ostr;
        ostr << FNS << "Host name '" << host << "' is too large";
        throw BrowserAddress::IDNAError(ostr.str());
      }

      bool has_unicode = false;
      wchar_t whost[MAX_HOSTNAME_SIZE];
      size_t whost_size = 0;
      for (SubString::SizeType i = 0; i < host.size();)
      {
        unsigned long octet_count =
          UTF8Handler::get_octet_count(host[i]);
        wchar_t wch;
        if (!UTF8Handler::utf8_char_to_wchar(&host[i],
          octet_count, wch))
        {
          Gears::ErrorStream ostr;
          ostr << FNS << "Invalid input sequence in host '" << host << "'";
          throw BrowserAddress::IDNAError(ostr.str());
        }
        if (octet_count > 1)
        {
          has_unicode = true;
        }
        whost[whost_size++] = wch;
        i += octet_count;
      }

      ascii.clear();
      unicode.clear();

      if (!has_unicode)
      {
        try
        {
          host.assign_to(ascii);
          idna_label_convert(host, host, IDNA0(ascii));
          unicode = ascii;
          return;
        }
        catch (const BrowserAddress::IDNAError&)
        {
          // We have 'xn--' prefix in a label,
          // additional processing is required
          has_unicode = true;
          ascii.clear();
        }
      }

      std::wstring normalized;
      if (!lower_and_normalize(
        WSubString(whost, whost_size), normalized, true))
      {
        Gears::ErrorStream ostr;
        ostr << FNS << "Normalization of host name '" << host << "' failed";
        throw BrowserAddress::IDNAError(ostr.str());
      }
      if (normalized.empty())
      {
        Gears::ErrorStream ostr;
        ostr << FNS << "Empty host name '" << host <<
          "' after normalization";
        throw BrowserAddress::IDNAError(ostr.str());
      }

      bool last_is_sep =
        normalized[normalized.size() - 1] == LABEL_SEPARATOR;

      ascii.reserve(normalized.size() * 4 + 1);
      unicode.reserve(normalized.size() * 4 + 1);

      idna_label_convert(host, WSubString(normalized),
        IDNA2008(ascii, unicode));

      if (ascii.size() >= MAX_HOSTNAME_SIZE)
      {
        Gears::ErrorStream ostr;
        ostr << FNS << "Resulted host name '" << ascii << "' is too large";
        throw BrowserAddress::IDNAError(ostr.str());
      }

      if (!last_is_sep)
      {
        ascii.resize(ascii.size() - 1);
        unicode.resize(unicode.size() - 1);
      }
    }

    bool
    idna_host_normalize(const SubString& url,
      const SubString& host, std::string& ascii, std::string& unicode,
      std::string& error)
    {
      try
      {
        idna_normalize_host(host, ascii, unicode);
      }
      catch (const BrowserAddress::IDNAError& ex)
      {
        error = ex.what();
        error.append(" in url '");
        url.append_to(error);
        error.push_back('\'');
        return false;
      }

      return true;
    }
  }

  namespace HTTP
  {
    const Ascii::Caseless HTTP_SCHEME("http");
    const Ascii::Caseless HTTPS_SCHEME("https");

    const Ascii::Caseless HTTP_PREFIX("http:");
    const Ascii::Caseless HTTPS_PREFIX("https:");

    const Ascii::Caseless HTTP_BEGIN("http://");
    const Ascii::Caseless HTTPS_BEGIN("https://");

    //
    // UrlParts class
    //

    UrlParts::UrlParts(const SubString& scheme,
      const SubString& userinfo, const SubString& host,
      const SubString& port, const SubString& path,
      const SubString& query, const SubString& fragment)
      throw ()
      : has_scheme(!scheme.empty()), scheme(scheme),
        has_userinfo(!userinfo.empty()), userinfo(userinfo),
        has_host(!host.empty()), host(host),
        has_port(!port.empty()), port(port),
        has_path(!path.empty()), path(path),
        has_query(!query.empty()), query(query),
        has_fragment(!fragment.empty()), fragment(fragment)
    {
    }

    //
    // ExtendedUrlParts class
    //

    void
    ExtendedUrlParts::clear() throw ()
    {
      has_scheme = false;
      scheme.clear();
      has_userinfo = false;
      userinfo.clear();
      has_host = false;
      host.clear();
      has_port = false;
      port.clear();
      has_path = false;
      path.clear();
      has_query = false;
      query.clear();
      has_fragment = false;
      fragment.clear();
      authority.clear();
    }

    void
    ExtendedUrlParts::split_url(const SubString& url)
    {
      clear();

      // Split URL into scheme, authority, path, query and fragment
      do
      {
        const char* const END = url.end();
        const char* cur = url.begin();
        const char* end;

        end = URL_PARSER_SCHEME_END.find_owned(cur, END);
        if (end == END)
        {
          has_path = true;
          path = url;
          break;
        }

        if (*end == ':')
        {
          has_scheme = true;
          scheme = SubString(cur, end);
          cur = end + 1;
          if (cur == END)
          {
            break;
          }
        }

        if (*cur != '?' && *cur != '#')
        {
          if (*cur == '/' && cur + 1 != END && cur[1] == '/')
          {
            cur += 2;
            if (cur == END)
            {
              break;
            }
            end = URL_PARSER_AUTORITY_END.find_owned(cur, END);
            authority = SubString(cur, end);
            if (end == END)
            {
              break;
            }
            cur = end;
          }
          end = URL_PARSER_PATH_END.find_owned(cur, END);
          has_path = true;
          path = SubString(cur, end);
          if (end == END)
          {
            break;
          }
          cur = end;
        }

        if (*cur == '?')
        {
          cur++;
          end = URL_PARSER_QUERY_END.find_owned(cur, END);
          has_query = true;
          query = SubString(cur, end);
          if (end == END)
          {
            break;
          }
          cur = end;
        }

        assert(*cur == '#');

        has_fragment = true;
        fragment = SubString(cur + 1, END);
      }
      while (false);

      // Split authority into userinfo, host and port
      if (!authority.empty())
      {
        SubString::SizeType host_begin =
          authority.find(USERINFO_SEPARATOR);
        if (host_begin != SubString::NPOS)
        {
          if (host_begin != 0)
          {
            has_userinfo = true;
            userinfo.assign(authority, 0, host_begin);
          }
          host_begin += USERINFO_SEPARATOR_SIZE;
        }
        else
        {
          host_begin = 0;
        }

        SubString::SizeType host_end =
          authority.rfind(PORT_SEPARATOR);
        if (host_end != SubString::NPOS && host_begin &&
          host_end < host_begin)
        {
          host_end = SubString::NPOS;
        }
        if (host_end != SubString::NPOS)
        {
          if (host_end != authority.length() - PORT_SEPARATOR_SIZE)
          {
            has_port = true;
            port.assign(authority, host_end + PORT_SEPARATOR_SIZE,
              authority.length() - host_end);
          }
        }
        else
        {
          host_end = authority.length();
        }
        has_host = true;
        host.assign(authority, host_begin, host_end - host_begin);
      }
    }

    //
    // URLPartsChecker class
    //

    bool
    URLPartsChecker::operator ()(const SubString& url,
      const UrlParts& parts, std::string& error)
    {
      // Check scheme
      if (parts.scheme.empty() ? parts.has_scheme :
        !SCHEME_FIRST.is_owned(parts.scheme[0]) ||
          !is_valid_chars(parts.scheme.substr(1), SCHEME_NOT_FIRST))
      {
        return make_invalid(error, "scheme in url", url);
      }

      // Check userinfo
      if (!parts.userinfo.empty())
      {
        if (!is_valid_encoded(parts.userinfo, USER_INFO))
        {
          return make_invalid(error, "userinfo in url", url);
        }
      }

      // Check host
      if (!parts.host.empty())
      {
        if (parts.host.size() > MAX_HOSTNAME_SIZE ||
          !is_valid_chars(parts.host, HOST))
        {
          return make_invalid(error, "host in url", url);
        }
        if (parts.host.size())
        {
          StringManip::Splitter<LabelSeparatorCategory, true> labels(
            parts.host[parts.host.size() - 1] == LABEL_SEPARATOR ?
              parts.host.substr(0, parts.host.size() - 1) : parts.host);
          SubString label;
          while (labels.get_token(label))
          {
            if (!label.size() || label.size() > MAX_HOSTNAME_LABEL_SIZE)
            {
              return make_invalid(error,
                "length of host's label in url", url);
            }
            if (!LABEL_FIRST_LAST(label[0]) ||
              (label.size() > 1 && !LABEL_FIRST_LAST(*(label.end() - 1))) ||
              (label.size() > 2 &&
                !is_valid_chars(label.substr(1, label.size() - 2),
                  LABEL_MIDDLE)))
            {
              return make_invalid(error,
                "characters in host's label in url", url);
            }
          }
        }
      }
      else
      {
        if (!parts.userinfo.empty() || !parts.port.empty())
        {
          return make_invalid(error, "empty host in url", url);
        }
      }

      // Check port
      if (!parts.port.empty())
      {
        if (!is_valid_chars(parts.port, PORT))
        {
          return make_invalid(error, "port in url", url);
        }
      }

      // Check path
      if (!parts.path.empty())
      {
        // Simplified check
        if ((!parts.host.empty() ? parts.path[0] != PATH_SEPARATOR :
          parts.path[0] == PATH_SEPARATOR && parts.path.size() > 1 &&
          parts.path[1] == PATH_SEPARATOR) ||
          !is_valid_encoded(parts.path, PATH))
        {
          return make_invalid(error, "path in url", url);
        }
      }

      // Check query
      if (!parts.query.empty())
      {
        if (!is_valid_encoded(parts.query, QUERY))
        {
          return make_invalid(error, "query in url", url);
        }
      }

      // Check fragment
      if (!parts.fragment.empty())
      {
        if (!is_valid_encoded(parts.fragment, FRAGMENT))
        {
          return make_invalid(error, "fragment in url", url);
        }
      }

      return true;
    }

    //
    // URLChecker class
    //

    bool
    URLChecker::operator ()(const SubString& url)
    {
      ExtendedUrlParts parts;
      parts.split_url(url);
      std::string error;
      return URLPartsChecker::operator ()(url, parts, error);
    }

    //
    // URLAddress class
    //

    URLAddress::URLAddress() throw ()
    {
    }

    URLAddress::URLAddress(const SubString& value)
    {
      url(value);
    }

    URLAddress::URLAddress(const std::string_view& value)
    {
      url(SubString(value.data(), value.size()));
    }

    URLAddress::URLAddress(const SubString& scheme,
      const SubString& userinfo, const SubString& host,
      const SubString& port, const SubString& path,
      const SubString& query, const SubString& fragment)
    {
      UrlParts parts(scheme, userinfo, host, port, path, query, fragment);
      assign_url_parts_(parts, true);
    }

    URLAddress::URLAddress(const URLAddress& another)
    {
      assign_url_parts_(another.parts_, false);
    }

    URLAddress&
    URLAddress::operator =(const URLAddress& another)
    {
      assign_url_parts_(another.parts_, false);
      return *this;
    }

    void
    URLAddress::url_without_check_(const SubString& value)
    {
      url_.clear();
      parts_.clear();

      if (value.empty())
      {
        return;
      }

      value.assign_to(url_);

      parts_.split_url(url_);
    }

    void
    URLAddress::specific_checks_()
    {
    }

    void
    URLAddress::url(const SubString& value)
    {
      assign_(value);
    }

    void
    URLAddress::assign_(const SubString& value)
    {
      url_without_check_(value);

      specific_checks_();

      std::string error;
      URLPartsChecker checker;
      if (!checker(url_, parts_, error))
      {
        Gears::ErrorStream ostr;
        ostr << FNS << error;
        throw InvalidURL(ostr.str());
      }
    }

    void
    URLAddress::assign_url_parts_(const UrlParts& parts, bool check)
    {
      // Assemble url
      std::string new_url;
      new_url.reserve(parts.scheme.size() + parts.userinfo.size() +
        parts.host.size() + parts.port.size() + parts.path.size() +
        parts.fragment.size() + ALL_SEPS_SIZE);
      if (!parts.scheme.empty())
      {
        parts.scheme.assign_to(new_url);
        new_url += SCHEME_SUFFIX;
      }
      bool has_authority =
        parts.has_userinfo || !parts.host.empty() || parts.has_port;
      size_t authority_size = 0;
      if (has_authority)
      {
        new_url += AUTHORITY_PREFIX;
        authority_size = new_url.size();
        // Append authority
        if (parts.has_userinfo)
        {
          parts.userinfo.append_to(new_url);
          new_url += USERINFO_SEPARATOR;
        }
        parts.host.append_to(new_url);
        if (parts.has_port)
        {
          new_url += PORT_SEPARATOR;
          parts.port.append_to(new_url);
        }
        authority_size = new_url.size() - authority_size;
      }
      parts.path.append_to(new_url);
      if (parts.has_query)
      {
        new_url += QUERY_SEPARATOR;
        parts.query.append_to(new_url);
      }
      if (parts.has_fragment)
      {
        new_url += FRAGMENT_SEPARATOR;
        parts.fragment.append_to(new_url);
      }

      // Check components
      if (check)
      {
        std::string error;
        URLPartsChecker checker;
        if (!checker(new_url, parts, error))
        {
          Gears::ErrorStream ostr;
          ostr << FNS << error;
          throw InvalidURL(ostr.str());
        }
      }
      new_url.swap(url_);

      // adjust parts to new url string
      parts_.clear();

      auto ptr = url_.data();

      if (!parts.scheme.empty())
      {
        parts_.has_scheme = true;
        parts_.scheme.assign(ptr, parts.scheme.size());
        ptr += parts.scheme.size() + SCHEME_SUFFIX_SIZE;
      }

      if (has_authority)
      {
        ptr += AUTHORITY_PREFIX_SIZE;
        parts_.authority.assign(ptr, authority_size);
        ptr += parts_.authority.size();
        auto host_begin = parts.userinfo.size();
        if (parts.has_userinfo)
        {
          parts_.has_userinfo = true;
          parts_.userinfo = parts_.authority.substr(0, parts.userinfo.size());
          host_begin += USERINFO_SEPARATOR_SIZE;
        }
        if (!parts.host.empty())
        {
          parts_.has_host = true;
          parts_.host =
            parts_.authority.substr(host_begin, parts.host.size());
        }
        if (parts.has_port)
        {
          parts_.has_port = true;
          parts_.port = parts_.authority.substr(
            parts_.authority.size() - parts.port.size(), parts.port.size());
        }
      }

      parts_.has_path = true;
      parts_.path.assign(ptr, parts.path.size());
      ptr += parts.path.size();

      if (parts.has_query)
      {
        parts_.has_query = true;
        ptr += QUERY_SEPARATOR_SIZE;
        parts_.query.assign(ptr, parts.query.size());
        ptr += parts.query.size();
      }

      if (parts.has_fragment)
      {
        parts_.has_fragment = true;
        ptr += FRAGMENT_SEPARATOR_SIZE;
        parts_.fragment.assign(ptr, parts.fragment.size());
      }
    }

    URLAddress*
    URLAddress::create_address(const SubString& url)
    {
      if (url.empty())
      {
        Gears::ErrorStream ostr;
        ostr << FNS << "url is empty";
        throw InvalidURL(ostr.str());
      }
      if (HTTP_PREFIX.start(url) || HTTPS_PREFIX.start(url))
      {
        return new HTTPAddress(url);
      }
      Gears::ErrorStream ostr;
      ostr << FNS << "unsupported protocol in url " << url;
      throw InvalidURL(ostr.str());
    }

    //
    // HTTPChecker class
    //

    bool
    HTTPChecker::operator ()(const SubString& url, std::string* error,
      bool strict)
    {
      ExtendedUrlParts parts;

      std::string error_message;
      std::string& error_ref = error ? *error : error_message;

      if (url.empty())
      {
        error_ref = "url is null";
        return false;
      }

      parts.split_url(url);

      std::string fixed_url;
      if (!strict && http_url_needs_prefix(parts.scheme, parts.host))
      {
        http_add_scheme(fixed_url, url);
        parts.split_url(fixed_url);
      }
      if (!process_parts_(url, parts, error_ref, strict) ||
        !check_http_url_components(
          url, parts.scheme, parts.host, error_ref, strict))
      {
        return false;
      }

      return URLPartsChecker::operator ()(url, parts, error_ref);
    }

    bool
    HTTPChecker::process_parts_(const SubString& /*url*/,
      ExtendedUrlParts& parts, std::string& /*error*/, bool strict)
    {
      if (!strict)
      {
        parts.has_userinfo = false;
        parts.userinfo.clear();
        parts.has_path = false;
        parts.path.clear();
        parts.has_query = false;
        parts.query.clear();
        parts.has_fragment = false;
        parts.fragment.clear();
      }

      return true;
    }

    //
    // HTTPAddress class
    //

    HTTPAddress::HTTPAddress(const SubString& url)
      : URLAddress(), strict_(true), port_number_(0), secure_(false),
        default_port_(true)
    {
      if (!url.empty())
      {
        assign_(url);
      }
    }

    HTTPAddress::HTTPAddress(const SubString& url, bool strict_url)
      : URLAddress(), strict_(strict_url), port_number_(0), secure_(false),
        default_port_(true)
    {
      if (!url.empty())
      {
        assign_(url);
      }
    }

    HTTPAddress::HTTPAddress(const SubString& host,
      const SubString& path, const SubString& query,
      const SubString& fragment, unsigned short port, bool secure,
      const SubString& userinfo)
      : URLAddress(), strict_(false), port_number_(0), secure_(false),
        default_port_(true)
    {
      set_(secure, userinfo, host, port ? port : get_default_port_(secure),
        path, query, fragment);
    }

    int
    HTTPAddress::get_default_port_(bool secure) throw ()
    {
      return secure ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT;
    }

    void
    HTTPAddress::set_(bool secure, const SubString& userinfo,
      const SubString& host, unsigned short port,
      const SubString& path, const SubString& query,
      const SubString& fragment)
    {
      if (host.empty())
      {
        default_port_ = true;
        port_number_ = 0;
        return;
      }

      secure_ = secure;
      port_number_ = port;
      default_port_ = port_number_ == get_default_port_(secure_);

      char port_buffer[32];

      UrlParts parts(secure ? HTTPS_SCHEME.str : HTTP_SCHEME.str, userinfo,
        host, default_port_ ? SubString() : SubString(
          port_buffer, snprintf(port_buffer, sizeof(port_buffer), "%hu",
            port_number_)),
        path.empty() ? DEFAULT_PATH : SubString(path), query,
        fragment);

      assign_url_parts_(parts, true);
    }

    void
    HTTPAddress::assign_(const SubString& http_url)
    {
      if (http_url.empty())
      {
        Gears::ErrorStream ostr;
        ostr << FNS << "url is nil";
        throw InvalidURL(ostr.str());
      }

      URLAddress::assign_(http_url);

      secure_ = scheme() == HTTPS_SCHEME;

      const SubString& port_str = port();
      if (!port_str.empty())
      {
        if (!StringManip::str_to_int(port_str, port_number_))
        {
          Gears::ErrorStream ostr;
          ostr << FNS << "invalid port value=" << port_str;
          throw InvalidURL(ostr.str());
        }
        default_port_ = false;
      }
      else
      {
        port_number_ = get_default_port_(secure_);
        default_port_ = true;
      }

      if (path().empty())
      {
        parts_.path = DEFAULT_PATH;
      }
    }

    void
    HTTPAddress::specific_checks_()
    {
      if (!strict_ && http_url_needs_prefix(scheme(), host()))
      {
        std::string fixed_url;
        http_add_scheme(fixed_url, url_);
        url_without_check_(fixed_url);
      }

      bool rebuild = additional_checks_();

      {
        std::string error;
        if (!check_http_url_components(
          url(), scheme(), host(), error, strict_))
        {
          Gears::ErrorStream ostr;
          ostr << FNS << error;
          throw InvalidURL(ostr.str());
        }
      }

      UrlParts new_parts(parts_);

      PartCheckInfo parts[] =
      {
        PartCheckInfo(new_parts.userinfo, USER_INFO),
        PartCheckInfo(new_parts.path, PATH),
        PartCheckInfo(new_parts.query, QUERY),
        PartCheckInfo(new_parts.fragment, FRAGMENT),
      };

      if (!strict_)
      {
        for (PartCheckInfo* part = parts;
          part != parts + sizeof(parts) / sizeof(*parts); part++)
        {
          if (http_fix_part(part->part, part->CHECKER, part->new_part))
          {
            part->part = part->new_part;
            rebuild = true;
          }
        }
      }

      if (rebuild)
      {
        assign_url_parts_(new_parts, false);
      }
    }

    bool
    HTTPAddress::additional_checks_()
    {
      return false;
    }

    const std::string&
    HTTPAddress::get_view(unsigned long flags, std::string& str) const
    {
      str.clear();
      str.reserve(url_.size() + 36);

      if (flags & VW_PROTOCOL)
      {
        if (parts_.has_scheme)
        {
          (secure_ ? HTTPS_PREFIX : HTTP_PREFIX).str.append_to(str);
        }
        str += AUTHORITY_PREFIX;
      }
      if (flags & VW_HOSTNAME)
      {
        if ((flags & VW_HOSTNAME_WWW) == VW_HOSTNAME_WWW &&
          !WWW.start(host()))
        {
          WWW.str.append_to(str);
        }
        host().append_to(str);
      }
      if ((flags & VW_PORT) || (!default_port_ && (flags & VW_NDEF_PORT)))
      {
        char port[8] = ":";
        snprintf(port + 1, sizeof(port) - 1, "%hu", port_number_);
        str += port;
      }
      if (flags & VW_PATH)
      {
        const SubString& path_ref = path();
        size_t path_len = path_ref.size();
        if ((flags & VW_STRIP_PATH) == VW_STRIP_PATH &&
          path_ref[path_len - 1] == PATH_SEPARATOR)
        {
          path_len -= PATH_SEPARATOR_SIZE;
        }
        str.append(path_ref.data(), path_len);
      }
      if (flags & VW_QUERY && parts_.has_query)
      {
        str += QUERY_SEPARATOR;
        query().append_to(str);
      }
      if (flags & VW_FRAGMENT && parts_.has_fragment)
      {
        str += FRAGMENT_SEPARATOR;
        fragment().append_to(str);
      }
      return str;
    }

    //
    // BrowserChecker class
    //

    bool
    BrowserChecker::process_parts_(const SubString& url,
      ExtendedUrlParts& parts, std::string& error, bool strict)
    {
      if (!HTTPChecker::process_parts_(url, parts, error, strict))
      {
        return false;
      }

      std::string unicode;
      if (!idna_host_normalize(url, parts.host, encoded_host_, unicode,
        error))
      {
        return false;
      }
      parts.host = encoded_host_;
      return true;
    }

    bool
    BrowserChecker::operator ()(const SubString& url,
      std::string* error)
    {
      return HTTPChecker::operator()(url, error, false);
    }


    //
    // BrowserAddress
    //

    BrowserAddress::BrowserAddress(const SubString& url)
      : HTTPAddress(SubString(), false)
    {
      if (!url.empty())
      {
        assign_(url);
      }
    }

    BrowserAddress::BrowserAddress(std::string_view url)
    {
      if (!url.empty())
      {
        assign_(SubString(url.data(), url.size()));
      }
    }

    BrowserAddress::BrowserAddress(const SubString& host,
      const SubString& path, const SubString& query,
      const SubString& fragment, unsigned short port, bool secure,
      const SubString& userinfo)
      : HTTPAddress()
    {
      process_host_(host);
      set_(secure, userinfo, encoded_host_,
        port ? port : HTTPAddress::get_default_port_(secure),
        path, query, fragment);
    }

    void
    BrowserAddress::process_host_(const SubString& host)
    {
      std::string error;
      if (!idna_host_normalize(url_, host, encoded_host_,
        decoded_host_, error))
      {
        Gears::ErrorStream ostr;
        ostr << FNS << error;
        throw InvalidURL(ostr.str());
      }
      parts_.host = encoded_host_;
    }

    bool
    BrowserAddress::additional_checks_()
    {
      process_host_(parts_.host);
      return true;
    }


    //
    // Functions
    //

    std::string
    normalize_http_address(const SubString& url)
    {
      std::string norm;

      BrowserAddress address(url);
      if (!address.secure() && address.port_number() == DEFAULT_HTTP_PORT)
      {
        HTTP_PREFIX.str.assign_to(norm);
        norm.append(AUTHORITY_PREFIX, AUTHORITY_PREFIX_SIZE);
        std::string tmp;
        address.host().assign_to(tmp);
        Ascii::to_lower(tmp);
        norm.append(tmp);
        unmime(address.path(), PATH, tmp);
        norm.append(tmp);
        if (!address.query().empty())
        {
          unmime(address.query(), QUERY, tmp);
          norm.push_back(QUERY_SEPARATOR);
          norm.append(tmp);
        }
      }

      return norm;
    }

    std::string
    keywords_from_http_address(const SubString& url)
    {
      ExtendedUrlParts parts;

      parts.split_url(url);

      std::string fixed_url;
      if (http_url_needs_prefix(parts.scheme, parts.host))
      {
        http_add_scheme(fixed_url, url);
        parts.split_url(fixed_url);
      }

      std::string keywords;

      std::string tmp, tmp2;
      idna_normalize_host(parts.host, tmp, keywords);
      unmime_all(parts.path, tmp);
      keywords.append(tmp);
      if (!parts.query.empty())
      {
        unmime_all(parts.query, tmp);
        keywords.push_back(QUERY_SEPARATOR);
        keywords.append(tmp);

        if(!tmp.empty())
        {
          unmime_all(tmp, tmp2);
          keywords.push_back(QUERY_SEPARATOR);
          keywords.append(tmp2);
        }
      }

      return keywords;
    }
  }
} // namespace Gears
