#pragma once

#include "AsciiStringManip.hpp"

namespace Gears
{
  namespace HTTP
  {
    extern const Ascii::Caseless HTTP_SCHEME;
    extern const Ascii::Caseless HTTPS_SCHEME;

    extern const Ascii::Caseless HTTP_PREFIX;
    extern const Ascii::Caseless HTTPS_PREFIX;

    extern const Ascii::Caseless HTTP_BEGIN;
    extern const Ascii::Caseless HTTPS_BEGIN;

    /**
     * Context object structure
     * URL is [scheme:][//[userinfo@]host[:port]][path][?query][#fragment]
     */
    struct UrlParts
    {
      bool has_scheme;
      SubString scheme;
      bool has_userinfo;
      SubString userinfo;
      bool has_host;
      SubString host;
      bool has_port;
      SubString port;
      bool has_path;
      SubString path;
      bool has_query;
      SubString query;
      bool has_fragment;
      SubString fragment;

      /**
       * Constructor
       * Initializes data members with default values
       */
      UrlParts() throw ();

      /**
       * Constructor
       * Initializes data members with the given values
       * @param scheme initial value for scheme data member
       * @param userinfo initial value for userinfo data member
       * @param host initial value for host data member
       * @param port initial value for port data member
       * @param path initial value for path data member
       * @param query initial value for query data member
       * @param fragment initial value for fragment data member
       */
      UrlParts(const SubString& scheme,
        const SubString& userinfo, const SubString& host,
        const SubString& port, const SubString& path,
        const SubString& query, const SubString& fragment)
        throw ();
    };

    /**
     * Extended context object with additional authority field and
     * function members.
     */
    struct ExtendedUrlParts : public UrlParts
    {
      SubString authority;

      /**
       * Resets data members to have default values
       */
      void
      clear() throw ();

      /**
       * Splits URL into its parts, parts are stored in data members.
       * @param url URL to split
       */
      void
      split_url(const SubString& url);
    };

    /**
     * Represent splitted URL. Verifies it upon splitting.
     */
    class URLAddress
    {
    public:
      DECLARE_EXCEPTION(Exception, DescriptiveException);
      DECLARE_EXCEPTION(InvalidURL, Exception);

      /**
       * Constructor
       */
      URLAddress() throw ();

      /**
       * Constructor
       * Splits the supplied URL and verifies it.
       */
      explicit
      URLAddress(const SubString& url);

      /**
       * Constructor
       * Uses previously splitted URL for initialization. Combines parts
       * to get full URL.
       * @param scheme scheme part of URL
       * @param userinfo userinfo part of URL
       * @param host host part of URL
       * @param port port part of URL
       * @param path path part of URL
       * @param query query part of URL
       * @param fragment fragment part of URL
       */
      URLAddress(const SubString& scheme,
        const SubString& userinfo, const SubString& host,
        const SubString& port, const SubString& path,
        const SubString& query, const SubString& fragment);

      /**
       * Copy constructor
       * @param another source URL object
       */
      URLAddress(const URLAddress& another);

      /**
       * Destructor
       */
      virtual
      ~URLAddress() throw ();

      /**
       * Assignment operator
       * @param another source URL object
       * @return reference to the object
       */
      URLAddress&
      operator =(const URLAddress& another);

      /**
       * Assigns new URL to object
       * @param value new URL to be assigned to object
       */
      void
      url(const SubString& value);

      /**
       * Full URL stored
       * @return full URL
       */
      const std::string&
      url() const throw ();

      /**
       * Scheme part of the URL
       * @return scheme part
       */
      const SubString&
      scheme() const throw ();

      /**
       * Authority part of the URL
       * @return authority part
       */
      const SubString&
      authority() const throw ();

      /**
       * Path part of the URL
       * @return path part
       */
      const SubString&
      path() const throw ();

      /**
       * Query part of the URL
       * @return query part
       */
      const SubString&
      query() const throw ();

      /**
       * Fragment part of the URL
       * @return fragment part
       */
      const SubString&
      fragment() const throw ();

      /**
       * Userinfo part of the URL
       * @return userinfo part
       */
      const SubString&
      userinfo() const throw ();

      /**
       * Host part of the URL
       * @return host part
       */
      const SubString&
      host() const throw ();

      /**
       * Port part of the URL
       * @return port part
       */
      const SubString&
      port() const throw ();


      /**
       * Creates object of URLAddress class or its descendant depending on the
       * scheme of the URL.
       * @param url URL to use
       * @return an object of the corresponding class
       */
      static
      URLAddress*
      create_address(const SubString& url);

    protected:
      virtual
      void
      assign_(const SubString& url);

      /**
       * Assembly URL from url parts and save it to url_
       * parts will set according new url_ value.
       */
      void
      assign_url_parts_(const UrlParts& parts, bool check);

      void
      url_without_check_(const SubString& url);

      virtual
      void
      specific_checks_();

      std::string url_;
      ExtendedUrlParts parts_;
    };

    /**
     * Expansion of URLAddress class to support HTTP URL details.
     * Uses strict checking.
     */
    class HTTPAddress : public URLAddress
    {
    public:
      /**
       * Constructor
       * Splits HTTP URL supplied and verifies it.
       * @param url HTTP URL
       */
      explicit
      HTTPAddress(const SubString& url = SubString());

      /**
       * Constructor
       * Uses splitted HTTP URL for initialization. Combines parts
       * to get full URL.
       * @param host host part of HTTP URL
       * @param path path part of HTTP URL
       * @param query query part of HTTP URL
       * @param fragment fragment part of HTTP URL
       * @param port port number of HTTP URL (0 - use default port)
       * @param secure whether scheme https and port 443 or http and 80 to use
       * by default
       * @param userinfo userinfo part of URL
       */
      HTTPAddress(const SubString& host,
        const SubString& path,
        const SubString& query = SubString(),
        const SubString& fragment = SubString(),
        unsigned short port = 0,
        bool secure = false,
        const SubString& userinfo = SubString());

      /**
       * Destructor
       */
      virtual
      ~HTTPAddress() throw () = default;

      /**
       * Port number of the HTTP URL
       * @return port number
       */
      unsigned short
      port_number() const throw ();

      /**
       * If HTTP URL uses secure scheme
       * @return whether secure or not
       */
      bool
      secure() const throw ();

      /**
       * If the port is default for the scheme
       * @return whether default port or not
       */
      bool
      is_default_port() const throw ();

      /**
       * Returns URL combined of the selected parts of the original URL
       * @param flags parts to combine
       * @param str string to place result to
       * @return reference to str
       */
      const std::string&
      get_view(unsigned long flags, std::string& str) const;

      enum VW_FLAGS
      {
        VW_PROTOCOL = 0x01,
        VW_HOSTNAME = 0x02,
        VW_HOSTNAME_WWW = (VW_HOSTNAME + 0x100),
        VW_PORT = 0x04,
        VW_NDEF_PORT = 0x08,
        VW_PATH = 0x10,
        VW_QUERY = 0x20,
        VW_STRIP_PATH = (VW_PATH + 0x40),
        VW_FRAGMENT = 0x80,

        VW_FULL = VW_PROTOCOL | VW_HOSTNAME | VW_NDEF_PORT |
          VW_PATH | VW_QUERY | VW_FRAGMENT
      };

    protected:
      HTTPAddress(const SubString& url,
        bool strict_url);

      static
      int
      get_default_port_(bool secure) throw ();

      virtual
      void
      assign_(const SubString& url);

      void
      set_(bool secure, const SubString& userinfo,
        const SubString& host, unsigned short port,
        const SubString& path, const SubString& query,
        const SubString& fragment);

      virtual
      void
      specific_checks_();

      virtual
      bool
      additional_checks_();

      bool strict_;
      unsigned short port_number_;
      bool secure_;
      bool default_port_;
    };

    /**
     * Expansion of HTTPAddress class to act as url in web browser.
     * Supports IDN and always non-strict
     */
    class BrowserAddress : public HTTPAddress
    {
    public:
      DECLARE_EXCEPTION(IDNAError, InvalidURL);

      /**
       * Constructor
       * Splits HTTP URL supplied and verifies it.
       * Converts host name with punicode if required.
       * @param url HTTP URL
       */
      explicit
      BrowserAddress(const SubString& url = SubString());

      /**
       * Constructor
       * Uses splitted HTTP URL for initialization. Combines parts
       * to get full URL.
       * @param host host part of HTTP URL. Encoded with punycode if required
       * @param path path part of HTTP URL
       * @param query query part of HTTP URL
       * @param fragment fragment part of HTTP URL
       * @param port port number of HTTP URL (0 - use default port)
       * @param secure whether scheme https and port 443 or http and 80 to use
       * by default
       * @param userinfo userinfo part of URL
       */
      BrowserAddress(const SubString& host,
        const SubString& path,
        const SubString& query = SubString(),
        const SubString& fragment = SubString(),
        unsigned short port = 0,
        bool secure = false,
        const SubString& userinfo = SubString());

      /**
       * Destructor
       */
      virtual
      ~BrowserAddress() throw () = default;

      /**
       * Unicode host part of the URL
       * @return unicode host part
       */
      SubString
      unicode_host() const throw ();

    protected:
      virtual
      bool
      additional_checks_();

      void
      process_host_(const SubString& host);

      std::string decoded_host_;
      std::string encoded_host_;
    };


    /**
     * Checker of URL parts for validness
     */
    class URLPartsChecker
    {
    public:
      /**
       * Checks URL parts for validness
       * @param url URL to use in error messages
       * @param parts URL parts to check for validness
       * @param error error message if URL is not valid
       * @return if supplied URL parts are valid
       */
      bool
      operator ()(const SubString& url, const UrlParts& parts,
        std::string& error);
    };

    /**
     * Checker of URL for validness
     */
    class URLChecker : protected URLPartsChecker
    {
    public:
      /**
       * Checks URL for validness
       * @param url URL to check for validness
       * @return if supplied URL is valid
       */
      bool
      operator ()(const SubString& url);
    };

    /**
     * Checker of HTTP URL for validness
     */
    class HTTPChecker : protected URLPartsChecker
    {
    public:
      /**
       * Destructor
       */
      virtual
      ~HTTPChecker() throw ();

      /**
       * Checks HTTP URL for validness
       * @param url HTTP URL to check for validness
       * @param error error message if URL is not valid
       * @param strict if prefix http:// or https:// is required
       * @return if supplied HTTP URL is valid
       */
      bool
      operator ()(const SubString& url, std::string* error = 0,
        bool strict = true);

    protected:
      virtual
      bool
      process_parts_(const SubString& url, ExtendedUrlParts& parts,
        std::string& error, bool strict);
    };

    /**
     * Checker of HTTP URL with IDN for validness
     */
    class BrowserChecker : protected HTTPChecker
    {
    public:
      /**
       * Destructor
       */
      virtual
      ~BrowserChecker() throw () = default;

      /**
       * Checks HTTP URL for validness
       * @param url HTTP URL to check for validness
       * @param error error message if URL is not valid
       * @return if supplied HTTP URL is valid
       */
      bool
      operator ()(const SubString& url, std::string* error = 0);

    protected:
      virtual
      bool
      process_parts_(const SubString& url, ExtendedUrlParts& parts,
        std::string& error, bool strict);

      std::string encoded_host_;
    };


    /**
     * Converts url into pseudo-normal form.
     * @param url url to convert
     * @return normalized url
     */
    std::string
    normalize_http_address(const SubString& url);

    /**
     * Fetch keywords from url
     * @param url url to convert
     * @return keywords from url
     */
    std::string
    keywords_from_http_address(const SubString& url);
  }
}

namespace Gears
{
  namespace HTTP
  {
    //
    // UrlParts class
    //

    inline
    UrlParts::UrlParts() throw ()
      : has_scheme(false), has_userinfo(false), has_host(false),
        has_port(false), has_path(false), has_query(false),
        has_fragment(false)
    {
    }


    //
    // URLAddress class
    //

    inline
    URLAddress::~URLAddress() throw ()
    {
    }

    inline
    const std::string&
    URLAddress::url() const throw ()
    {
      return url_;
    }

    inline
    const SubString&
    URLAddress::scheme() const throw ()
    {
      return parts_.scheme;
    }

    inline
    const SubString&
    URLAddress::authority() const throw ()
    {
      return parts_.authority;
    }

    inline
    const SubString&
    URLAddress::path() const throw ()
    {
      return parts_.path;
    }

    inline
    const SubString&
    URLAddress::query() const throw ()
    {
      return parts_.query;
    }

    inline
    const SubString&
    URLAddress::fragment() const throw ()
    {
      return parts_.fragment;
    }

    inline
    const SubString&
    URLAddress::userinfo() const throw ()
    {
      return parts_.userinfo;
    }

    inline
    const SubString&
    URLAddress::host() const throw ()
    {
      return parts_.host;
    }

    inline
    const SubString&
    URLAddress::port() const throw ()
    {
      return parts_.port;
    }


    //
    // HTTPAddress class
    //

    inline
    unsigned short
    HTTPAddress::port_number() const throw ()
    {
      return port_number_;
    }

    inline
    bool
    HTTPAddress::secure() const throw ()
    {
      return secure_;
    }

    inline
    bool
    HTTPAddress::is_default_port() const throw ()
    {
      return default_port_;
    }


    //
    // BrowserAddress
    //

    inline
    SubString
    BrowserAddress::unicode_host() const throw ()
    {
      return decoded_host_;
    }


    //
    // HTTPChecker class
    //

    inline
    HTTPChecker::~HTTPChecker() throw ()
    {
    }
  }
}
