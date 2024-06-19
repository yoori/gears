#include <mutex>

#include <gears/Time.hpp>
#include <gears/Uuid.hpp>
#include <gears/ISAAC.hpp>

namespace Gears
{
  namespace
  {
    std::mutex global_mutex;

    uint8_t
    random_byte() throw () // Called under mutex
    {
      static ISAAC generator;
      return static_cast<uint8_t>(generator.rand() >> 24);
    }
  }

  const Uuid::size_type Uuid::DATA_SIZE;

  Uuid::Uuid() throw ()
  {
    std::fill(data_, data_ + sizeof(data_), 0);
  }

  template <typename Iterator>
  Iterator
  Uuid::construct_(Iterator begin, Iterator end, bool padding)
    /*throw (Gears::Exception, Exception, InvalidArgument)*/
  {
    static const char* FUN = "Uuid::construct_()";

    size_type size = encoded_size(padding);
    std::string src;
    src.reserve(size);
    while (size--)
    {
      if (begin == end)
      {
        Gears::ErrorStream ostr;
        ostr << FUN << ": Uuid string is too short";
        throw InvalidArgument(ostr.str());
      }
      src.push_back(*begin);
      ++begin;
    }
    std::string result;
    Gears::StringManip::base64mod_decode(result, src, padding);
    *this = Uuid(result.data(), result.data() + result.size());

    return begin;
  }

  void
  Uuid::construct_(const Gears::SubString& str, bool padding)
    /*throw (Gears::Exception, Exception, InvalidArgument)*/
  {
    static const char* FUN = "Uuid::construct_()";

    if (construct_(str.begin(), str.end(), padding) != str.end())
    {
      Gears::ErrorStream ostr;
      ostr << FUN << ": Uuid string contains extra symbols";
      throw InvalidArgument(ostr.str());
    }
  }

  Uuid::Uuid(const char* str, bool padding)
    /*throw (Gears::Exception, Exception, InvalidArgument)*/
  {
    construct_(Gears::SubString(str), padding);
  }

  Uuid::Uuid(const Gears::SubString& str, bool padding)
    /*throw (Gears::Exception, Exception, InvalidArgument)*/
  {
    construct_(str, padding);
  }

  Uuid::Uuid(std::istream& istr)
    /*throw (Gears::Exception, Exception, InvalidArgument)*/
  {
    construct_(std::istreambuf_iterator<char>(istr),
      std::istreambuf_iterator<char>(0), true);
  }

  std::string
  Uuid::to_string(bool padding) const /*throw (Gears::Exception)*/
  {
    std::string str;
    Gears::StringManip::base64mod_encode(str, data_, DATA_SIZE, padding);
    return str;
  }

  std::ostream&
  operator <<(std::ostream& ostr, const Uuid& uuid) throw ()
  {
    std::ostream::sentry ok(ostr);
    if (ok)
    {
      try
      {
        ostr << uuid.to_string(true);
      }
      catch (const Gears::Exception&)
      {
        ostr.setstate(std::ios_base::failbit);
      }
    }
    return ostr;
  }

  std::istream&
  operator >>(std::istream& istr, Uuid& uuid) throw ()
  {
    std::istream::sentry ok(istr);
    if (ok)
    {
      try
      {
        uuid = Uuid(istr);
      }
      catch (const Gears::Exception&)
      {
        istr.setstate(std::ios_base::failbit);
      }
    }
    return istr;
  }

  //random number based
  Uuid
  Uuid::create_random_based() throw ()
  {
    Uuid result;

    {
      std::unique_lock<std::mutex> lock(global_mutex);
      for (size_type i = 0; i < size(); ++i)
      {
        result.data_[i] = random_byte();
      }
    }

    // This code need for RFC 4122 compliance... see 4.4. paragraph.
    // set variant
    // should be 0b10xxxxxx
    result.data_[8] &= 0xBF;
    result.data_[8] |= 0x80;

    // set version
    // should be 0b0100xxxx
    result.data_[6] &= 0x4F; //0b01001111
    result.data_[6] |= 0x40; //0b01000000

    return result;
  }

} // namespace Gears
