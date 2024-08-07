#include <map>

#include <gears/StringManip.hpp>
#include <gears/TextTemplate.hpp>
#include <gears/MMapStream.hpp>

namespace Gears
{
namespace TextTemplate
{
  //
  // Basic::Item class
  //

  Basic::Item::~Item() noexcept
  {}

  //
  // Basic::StringItem class
  //

  Basic::StringItem::StringItem(const SubString& val)
    /*throw (Gears::Exception)*/
    : value_(val)
  {}

  Basic::StringItem::~StringItem() noexcept
  {}

  void
  Basic::StringItem::append_value(
    const ArgsCallback& /*callback*/,
    std::string& dst) const /*throw (Gears::Exception)*/
  {
    value_.append_to(dst);
  }

  std::string
  Basic::StringItem::key(const ArgsCallback& /*callback*/) const
    /*throw (Gears::Exception)*/
  {
    return std::string();
  }

  //
  // Basic::VarItem class
  //

  Basic::VarItem::VarItem(const SubString& key) /*throw (Gears::Exception)*/
    : key_(key)
  {}

  Basic::VarItem::~VarItem() noexcept
  {}

  void
  Basic::VarItem::append_value(
    const ArgsCallback& callback,
    std::string& dst) const /*throw (Gears::Exception)*/
  {
    static const char* FUN = "Basic::VarItem::append_value()";

    std::string result;
    if (!callback.get_argument(key_, result))
    {
      ErrorStream ostr;
      ostr << FUN << ": failed to substitute key '" << key_ << "'";
      throw UnknownName(ostr.str());
    }
    dst += result;
  }

  std::string
  Basic::VarItem::key(const ArgsCallback& callback) const
    /*throw (Gears::Exception)*/
  {
    std::string result;
    callback.get_argument(key_, result, false);
    return result;
  }

  //
  // SubString class
  //

  const SubString Basic::DEFAULT_LEXEME("%%", 2);

  Basic::Basic(
    const SubString& str,
    const SubString& start_lexeme,
    const SubString& end_lexeme)
    /*throw (InvalidTemplate, TextTemplException, Gears::Exception)*/
  {
    init(str, start_lexeme, end_lexeme);
  }

  void
  Basic::init(
    const SubString& source,
    const SubString& start_lexeme,
    const SubString& end_lexeme)
    /*throw (InvalidTemplate, TextTemplException, Gears::Exception)*/
  {
    static const char* FUN = "TextTemplate::Basic::init()";

    items_.clear();

    if (start_lexeme.empty())
    {
      ErrorStream ostr;
      ostr << FUN << ": empty start_lexeme.";
      throw TextTemplException(ostr.str());
    }

    if (end_lexeme.empty())
    {
      ErrorStream ostr;
      ostr << FUN << ": empty end_lexeme.";
      throw TextTemplException(ostr.str());
    }

    SubString str(source);

    // Split a template string on keys into items
    // and create the list from them.
    while (!str.empty())
    {
      SubString::SizeType begin = str.find(start_lexeme);

      if (begin == SubString::NPOS)
      {
        items_.push_back(Item_var(new StringItem(str)));
        break;
      }

      items_.push_back(Item_var(new StringItem(str.substr(0, begin))));

      begin += start_lexeme.length();

      SubString::SizeType end = str.find(end_lexeme, begin);
      if (end == SubString::NPOS)
      {
        ErrorStream ostr;
        ostr << FUN <<
          ": invalid template: closing lexeme (" << end_lexeme <<
          ") not found. Template:\n'" << source << "'";
        throw InvalidTemplate(ostr.str());
      }

      items_.push_back(
        Item_var(
          new VarItem(str.substr(begin, end - begin))));

      str = str.substr(end + end_lexeme.length());
    }
  }

  std::string
  Basic::instantiate(const ArgsCallback& args) const
    /*throw (UnknownName, TextTemplException, Gears::Exception)*/
  {
    std::string str;

    // Replace keys with values
    for (Items::const_iterator it = items_.begin();
      it != items_.end(); ++it)
    {
      (*it)->append_value(args, str);
    }

    return str;
  }

  void
  Basic::keys(const ArgsCallback& args, Keys& keys) const
    /*throw (UnknownName, TextTemplException, Gears::Exception)*/
  {
    keys.clear();
    for (Items::const_iterator it = items_.begin();
      it != items_.end(); ++it)
    {
      std::string&& name = (*it)->key(args);
      if (!name.empty())
      {
        keys.insert(std::move(name));
      }
    }
  }


  //
  // String class
  //

  void
  String::init(
    const SubString& str,
    const SubString& start_lexeme,
    const SubString& end_lexeme)
    /*throw (InvalidTemplate, TextTemplException, Gears::Exception)*/
  {
    str.assign_to(text_template_);

    Basic::init(text_template_, start_lexeme, end_lexeme);
  }

  String::String(
    const SubString& str,
    const SubString& start_lexeme,
    const SubString& end_lexeme)
    /*throw (InvalidTemplate, TextTemplException, Gears::Exception)*/
  {
    init(str, start_lexeme, end_lexeme);
  }

  //
  // IStream class
  //

  void
  IStream::init(
    std::istream& istr,
    const SubString& start_lexeme,
    const SubString& end_lexeme)
    /*throw (InvalidTemplate, TextTemplException, Gears::Exception)*/
  {
    static const char* FUN = "TextTemplate::IStream::init()";

    // Create a big string from a template file.
    std::getline(istr, text_template_, '\0');
    if (istr.bad() || !istr.eof())
    {
      ErrorStream ostr;
      ostr << FUN << ": unable to read from istream.";
      throw TextTemplException(ostr.str());
    }

    Basic::init(text_template_, start_lexeme, end_lexeme);
  }

  IStream::IStream(
    std::istream& istr,
    const SubString& start_lexeme,
    const SubString& end_lexeme)
    /*throw (InvalidTemplate, TextTemplException, Gears::Exception)*/
  {
    init(istr, start_lexeme, end_lexeme);
  }

  namespace
  {
    /**
     * utf-8 => utf-8 encoder
     * @param value string for convertation
     * @param encoded resulted encoded string
     */
    void
    encode_utf8_(std::string&& value, std::string& encoded)
      /*throw (Gears::Exception)*/
    {
      encoded = std::move(value);
    }

    /**
     * utf-8 => xml encoder
     * @param value string for conversion
     * @param encoded resulted encoded string
     */
    void
    encode_xml_(std::string&& value, std::string& encoded)
      /*throw (StringManip::InvalidFormatException, Gears::Exception)*/
    {
      StringManip::xml_encode(value.c_str(), encoded);
    }

    void
    encode_mime_(std::string&& value, std::string& encoded)
      /*throw (StringManip::InvalidFormatException, Gears::Exception)*/
    {
      StringManip::mime_url_encode(value, encoded);
    }

    void
    encode_js_unicode_(std::string&& value, std::string& encoded)
      /*throw (StringManip::InvalidFormatException, Gears::Exception)*/
    {
      StringManip::js_unicode_encode(value.c_str(), encoded);
    }

    void
    encode_js_(std::string&& value, std::string& encoded)
      /*throw (StringManip::InvalidFormatException, Gears::Exception)*/
    {
      StringManip::js_encode(value.c_str(), encoded);
    }

    /**
     * EncoderHolder class is a holder of default encoders
     */
    class EncoderHolder
    {
    public:
      /**
       * Finds previously registered encoder by the key
       * @param key unique keys determining encoder
       * @return Previously registered encoder associated with the key
       or zero if not found
      */
      Args::ValueEncoder
      get_value_encoder(const SubString& key) const noexcept;

      /**
       * Performs registration of encoder
       * @param key the unique key
       * @param encoder encoder associated with the key
       */
      void
      register_value_encoder(
        const char* key,
        Args::ValueEncoder encoder) /*throw (Gears::Exception)*/;

    private:
      typedef std::map<const SubString, Args::ValueEncoder> RelationType;

      RelationType relation_;
    };

    inline
    Args::ValueEncoder
    EncoderHolder::get_value_encoder(const SubString& key) const noexcept
    {
      RelationType::const_iterator found(relation_.find(key));
      return found == relation_.end() ? 0 : found->second;
    }

    inline
    void
    EncoderHolder::register_value_encoder(const char* key,
                                          Args::ValueEncoder encoder) /*throw (Gears::Exception)*/
    {
      relation_[SubString(key)] = encoder;
    }

    /**
     * Global encoder holder
     */
    EncoderHolder encoder_holder;
  }

  //
  // DefaultValue class
  //

  DefaultValue::DefaultValue(const ArgsCallback* callback) noexcept
    : callback_(callback)
  {}

  bool
  DefaultValue::get_argument(
    const SubString& key,
    std::string& result,
    bool value) const /*throw (Gears::Exception)*/
  {
    SubString::SizeType pos = key.find('=');

    if (pos == 0)
    {
      return false;
    }

    if (pos == SubString::NPOS)
    {
      return callback_->get_argument(key, result, value);
    }

    if (callback_->get_argument(key.substr(0, pos), result, value))
    {
      return true;
    }

    (value ? key.substr(pos + 1) : key.substr(0, pos)).assign_to(result);
    return true;
  }

  //
  // ArgsEncoder::EncoderItem class
  //

  ArgsEncoder::EncoderItem::EncoderItem(
    const char* key,
    ValueEncoder encoder) /*throw (Gears::Exception)*/
    : encoder_(encoder)
  {
    assert(key);
    encoder_holder.register_value_encoder(key, encoder);
  }

  //
  // ArgsEncoder class
  //

  /**X
   * Default encodings
   */
  const ArgsEncoder::EncoderItem
  ArgsEncoder::EI_UTF8("utf8", encode_utf8_);

  const ArgsEncoder::EncoderItem
  ArgsEncoder::EI_MIME_URL("mime-url", encode_mime_);

  const ArgsEncoder::EncoderItem
  ArgsEncoder::EI_XML("xml", encode_xml_);

  const ArgsEncoder::EncoderItem
  ArgsEncoder::EI_JS_UNICODE("js-unicode", encode_js_unicode_);

  const ArgsEncoder::EncoderItem
  ArgsEncoder::EI_JS("js", encode_js_);

  ArgsEncoder::ArgsEncoder(
    ArgsCallback* args_container,
    bool encode,
    bool error_if_no_key,
    const EncoderItem& default_encoding)
    /*throw (UnknownName, Gears::Exception)*/
    : args_container_(args_container),
      ENCODE_(encode),
      ERROR_IF_NO_KEY_(error_if_no_key),
      DEFAULT_ENCODER_(default_encoding.get_encoder_())
  {
    static const char* FUN = "TextTemplate::ArgsEncoder::ArgsEncoder()";

    if (!DEFAULT_ENCODER_)
    {
      ErrorStream ostr;
      ostr << FUN << ": invalid key";
      throw UnknownName(ostr.str());
    }
  }

  void
  ArgsEncoder::set_callback(ArgsCallback* args_container) noexcept
  {
    args_container_ = args_container;
  }

  bool
  ArgsEncoder::get_argument(
    const SubString& key,
    std::string& result,
    bool value) const /*throw (Gears::Exception)*/
  {
    if (key.empty())
    {
      return false;
    }

    ValueEncoder encoder = DEFAULT_ENCODER_;

    SubString key_val(key);

    if (ENCODE_)
    {
      SubString::SizeType pos = key_val.find(':');
      if (pos != SubString::NPOS)
      {
        ValueEncoder found =
          encoder_holder.get_value_encoder(key_val.substr(0, pos));
        if (found)
        {
          encoder = found;
          key_val = key_val.substr(pos + 1);
        }
      }
    }

    std::string found;

    if (!args_container_->get_argument(key_val, found, value))
    {
      if (ERROR_IF_NO_KEY_)
      {
        return false;
      }
      else
      {
        if (value)
        {
          result.clear();
        }
        else
        {
          key_val.assign_to(result);
        }
        return true;
      }
    }

    if (!value)
    {
      result = std::move(found);
      return true;
    }

    // Special case: no encode
    if (encoder == EI_UTF8.get_encoder_())
    {
      result = std::move(found);
      return true;
    }

    (*encoder)(std::move(found), result);

    return true;
  }

  //
  // Args class
  //

  Args::Args(
    bool encode,
    unsigned long table_size,
    bool error_if_no_key,
    const EncoderItem& default_encoding,
    bool has_defaults) /*throw (UnknownName, Gears::Exception)*/
    : ArgsEncoder(0, encode, error_if_no_key, default_encoding),
      ValueContainer(table_size), args_container_(this),
      default_value_callback_(&args_container_)
  {
    ArgsCallback* callback = &args_container_;
    if (has_defaults)
    {
      callback = &default_value_callback_;
    }
    set_callback(callback);
  }

  //
  // UpdateStrategy class
  //

  void
  UpdateStrategy::update()
    /*throw (TextTemplException, Gears::Exception)*/
  {
    static const char* FUN = "TextTemplate::UpdateStrategy::update()";

    try
    {
      MMapFileStream file(fname_.c_str());

      try
      {
        text_template_.init(file, start_lexeme(), end_lexeme());
      }
      catch (const TextTemplException& ex)
      {
        ErrorStream ostr;
        ostr << FUN << ": failed to initialize with file " << fname_ <<
          ": " << ex.what();
        throw TextTemplException(ostr.str());
      }
    }
    catch (const TextTemplException&)
    {
      throw;
    }
    catch (const Gears::Exception& ex)
    {
      ErrorStream ostr;
      ostr << FUN << ": failed to open file '" << fname_ << "': " <<
        ex.what();
      throw TextTemplException(ostr.str());
    }
  }
}
}
