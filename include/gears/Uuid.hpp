#pragma once

#include <ios>

#include "StringManip.hpp"

namespace Gears
{
  class Uuid
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);
    DECLARE_EXCEPTION(InvalidArgument, Exception);

    typedef uint8_t value_type;
    typedef value_type& reference_type;
    typedef const value_type& const_reference_type;
    typedef value_type* iterator;
    typedef const value_type* const_iterator;
    typedef ssize_t difference_type;
    typedef size_t size_type;

    // random number based
    static
    Uuid
    create_random_based() noexcept;

    Uuid() noexcept;

    explicit
    Uuid(const char* str, bool padding = true)
      /*throw (Gears::Exception, Exception, InvalidArgument)*/;

    explicit
    Uuid(const Gears::SubString& str, bool padding = true)
      /*throw (Gears::Exception, Exception, InvalidArgument)*/;

    explicit
    Uuid(std::istream& istr)
      /*throw (Gears::Exception, Exception, InvalidArgument)*/;

    template <typename ByteInputIterator>
    Uuid(ByteInputIterator first, ByteInputIterator last)
      /*throw (Gears::Exception, Exception, InvalidArgument)*/;

    bool
    operator ==(const Uuid& rhs) const noexcept;

    bool
    operator !=(const Uuid& rhs) const noexcept;

    bool
    operator <(const Uuid& rhs) const noexcept;

    bool
    operator >(const Uuid& rhs) const noexcept;

    bool
    operator <=(const Uuid& rhs) const noexcept;

    bool
    operator >=(const Uuid& rhs) const noexcept;

    bool
    is_null() const noexcept;

    std::string
    to_string(bool padding = true) const
      /*throw (Gears::Exception)*/;

    static
    size_type
    size() noexcept;

    static
    size_type
    encoded_size(bool padding = true) noexcept;

    iterator
    begin() noexcept;

    const_iterator
    begin() const noexcept;

    iterator
    end() noexcept;

    const_iterator
    end() const noexcept;

    void
    swap(Uuid& rhs) noexcept;

    unsigned long
    hash() const noexcept;

  private:
    static const size_type DATA_SIZE = 16;
    typedef value_type DataType[DATA_SIZE];

    template <typename Iterator>
    Iterator
    construct_(Iterator begin, Iterator end, bool padding)
      /*throw (Gears::Exception, Exception, InvalidArgument)*/;

    void
    construct_(const Gears::SubString& str, bool padding)
      /*throw (Gears::Exception, Exception, InvalidArgument)*/;

    union
    {
      DataType data_;
      uint64_t hash_[2];
    };
  }
# ifdef __GNUC__
  __attribute__ ((packed))
# endif
  ;

  std::ostream&
  operator <<(std::ostream& ostr, const Uuid& uuid) noexcept;
  std::istream&
  operator >>(std::istream& istr, Uuid& uuid) noexcept;

  template <typename Hash>
  void
  hash_add(Hash& hash, const Uuid& value) noexcept;
}

namespace Gears
{
  //
  // Uuid class
  //

  template <typename ByteInputIterator>
  Uuid::Uuid(ByteInputIterator first, ByteInputIterator last)
    /*throw (Gears::Exception, Exception, InvalidArgument)*/
  {
    static const char* FUN = "Uuid::Uuid()";

    size_t i = 0;
    for (; i < DATA_SIZE && first != last; ++i)
    {
      data_[i] = static_cast<value_type>(*first++);
    }
    if (i != DATA_SIZE)
    {
      Gears::ErrorStream ostr;
      ostr << FUN << ": invalid input Uuid iterator pair, must span 16 bytes";
      throw InvalidArgument(ostr.str());
    }
  }

  inline
  bool
  Uuid::operator ==(const Uuid& rhs) const noexcept
  {
    for (size_t i = 0; i < DATA_SIZE; i++)
    {
      if (data_[i] != rhs.data_[i])
      {
        return false;
      }
    }
    return true;
  }

  inline
  bool
  Uuid::operator !=(const Uuid& rhs) const noexcept
  {
    return !operator ==(rhs);
  }

  inline
  bool
  Uuid::operator <(const Uuid& rhs) const noexcept
  {
    for (size_t i = 0; i < DATA_SIZE; i++)
    {
      if (data_[i] < rhs.data_[i])
      {
        return true;
      }
      if (data_[i] > rhs.data_[i])
      {
        break;
      }
    }
    return false;
  }

  inline
  bool
  Uuid::operator >(const Uuid& rhs) const noexcept
  {
    return rhs < *this;
  }

  inline
  bool
  Uuid::operator <=(const Uuid& rhs) const noexcept
  {
    return !operator >(rhs);
  }

  inline
  bool
  Uuid::operator >=(const Uuid& rhs) const noexcept
  {
    return !operator <(rhs);
  }

  inline
  bool
  Uuid::is_null() const noexcept
  {
    for (size_t i = 0; i < DATA_SIZE; i++)
    {
      if (data_[i] != 0)
      {
        return false;
      }
    }

    return true;
  }

  inline
  Uuid::size_type
  Uuid::size() noexcept
  {
    return DATA_SIZE;
  }

  inline
  Uuid::size_type
  Uuid::encoded_size(bool padding) noexcept
  {
    return Gears::StringManip::base64mod_encoded_size(DATA_SIZE, padding);
  }

  inline
  Uuid::iterator
  Uuid::begin() noexcept
  {
    return data_;
  }

  inline
  Uuid::const_iterator
  Uuid::begin() const noexcept
  {
    return data_;
  }

  inline
  Uuid::iterator
  Uuid::end() noexcept
  {
    return data_ + DATA_SIZE;
  }

  inline
  Uuid::const_iterator
  Uuid::end() const noexcept
  {
    return data_ + DATA_SIZE;
  }

  inline
  void
  Uuid::swap(Uuid& rhs) noexcept
  {
    DataType data;
    std::copy(begin(), end(), data);
    std::copy(rhs.begin(), rhs.end(), data_);
    std::copy(data, data + sizeof(data), rhs.data_);
  }

  inline
  unsigned long
  Uuid::hash() const noexcept
  {
    return hash_[1];
  }


  template <typename Hash>
  void
  hash_add(Hash& hash, const Uuid& value) noexcept
  {
    hash.add(value.begin(), value.size());
  }

} // namespace Gears

