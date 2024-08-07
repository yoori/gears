#ifndef GEARS_ARRAYAUTOPTR_HPP
#define GEARS_ARRAYAUTOPTR_HPP

#include "Exception.hpp"

namespace Gears
{
  template <typename T>
  class ArrayAutoPtr;

  /**
   * An ArrayAutoPtr provides semantic of
   * STRICT OWNERSHIP over an array pointer.
   */
  template <typename T>
  class ArrayAutoPtr
  {
  public:
    typedef T ElementType;

    /**
     * Constructor
     */
    ArrayAutoPtr() noexcept;

    /**
     * Constructor
     * @param size size of the array to allocate (zero - not to allocate)
     */
    explicit
    ArrayAutoPtr(unsigned size) /*throw (Gears::Exception)*/;

    ArrayAutoPtr(ArrayAutoPtr&) noexcept = delete;

    /**
     * Move constructor
     * Transforms ownership from src to the constructed object
     * @param src former owner of the array
     */
    ArrayAutoPtr(ArrayAutoPtr&& src) noexcept;

    /**
     * Destructor
     * Deallocates owned array
     */
    ~ArrayAutoPtr() noexcept;

    ArrayAutoPtr&
    operator =(ArrayAutoPtr& src) noexcept = delete;

    /**
     * Assignment operator
     * Transforms ownership from src to the object
     * @param src former owner of the array
     */
    ArrayAutoPtr&
    operator =(ArrayAutoPtr&& src) noexcept;

    /**
     * Accessor for the array
     * @return pointer to stored array
     */
    T*
    get() const noexcept;

    /**
     * Accessor for element of the array
     * @param index index of the required element of the array
     * @return reference to element
     */
    T&
    operator [](unsigned index) noexcept;

    /**
     * Accessor for constant element of the array
     * @param index index of the required element of the array
     * @return constant reference to element
     */
    const T&
    operator [](unsigned index) const noexcept;

    /**
     * Releases ownership
     * @return previously stored pointer to the array
     */
    T*
    release() noexcept;

    /**
     * Releases stored array (if any) and allocated a new one (if size is
     * positive)
     * @param size size of a new array
     */
    void
    reset(unsigned size) /*throw (Gears::Exception)*/;

    /**
     * Releases stored array (if any) and resets the pointer with a new one.
     * May lead to problems (if ptr is not pointer to array of T).
     * @param ptr new pointer to hold
     */
    void
    unsafe_reset(T* ptr) noexcept;

    /**
     * Never implemented thus usage will lead to error messages.
     */
    template <typename U>
    void
    unsafe_reset(U*) noexcept = delete;

    /**
     * Swaps pointers of the object and src
     * @param src another object to swap pointers with
     */
#if __GNUC__ == 4 && __GNUC_MINOR__ == 4
    void
    swap(ArrayAutoPtr&& src) noexcept;
#else
    void
    swap(ArrayAutoPtr& src) noexcept;
#endif

  private:
    T* ptr_;
  };


  //typedef ArrayAutoPtr<char> ArrayChar;
  typedef ArrayAutoPtr<unsigned char> ArrayByte;
  typedef ArrayAutoPtr<wchar_t> ArrayWChar;
}

// Implementation
namespace Gears
{
  //
  // ArrayAutoPtr class
  //

  template <typename T>
  T*
  ArrayAutoPtr<T>::get() const noexcept
  {
    return ptr_;
  }

  template <typename T>
  T&
  ArrayAutoPtr<T>::operator [](unsigned index) noexcept
  {
    return ptr_[index];
  }

  template <typename T>
  const T&
  ArrayAutoPtr<T>::operator [](unsigned index) const noexcept
  {
    return ptr_[index];
  }

  template <typename T>
  T*
  ArrayAutoPtr<T>::release() noexcept
  {
    T* ptr(ptr_);
    ptr_ = 0;

    return ptr;
  }

  template <typename T>
  void
  ArrayAutoPtr<T>::unsafe_reset(T* ptr) noexcept
  {
    if (ptr_ != ptr)
    {
      if (ptr_)
      {
        delete [] ptr_;
      }

      ptr_ = ptr;
    }
  }

  template <typename T>
  void
  ArrayAutoPtr<T>::reset(unsigned size) /*throw (Gears::Exception)*/
  {
    T* ptr = size ? new T[size] : 0;

    if (ptr_)
    {
      delete [] ptr_;
    }

    ptr_ = ptr;
  }

  template <typename T>
  void
#if __GNUC__ == 4 && __GNUC_MINOR__ == 4
  ArrayAutoPtr<T>::swap(ArrayAutoPtr&& src) noexcept
#else
  ArrayAutoPtr<T>::swap(ArrayAutoPtr& src) noexcept
#endif
  {
    std::swap(ptr_, src.ptr_);
  }

  template <typename T>
  ArrayAutoPtr<T>::ArrayAutoPtr() noexcept
    : ptr_(0)
  {
  }

  template <typename T>
  ArrayAutoPtr<T>::ArrayAutoPtr(unsigned size) /*throw (Gears::Exception)*/
    : ptr_(size ? new T[size] : 0)
  {
  }

  template <typename T>
  ArrayAutoPtr<T>::ArrayAutoPtr(ArrayAutoPtr&& src) noexcept
    : ptr_(src.release())
  {
  }

  template <typename T>
  ArrayAutoPtr<T>&
  ArrayAutoPtr<T>::operator =(ArrayAutoPtr&& src) noexcept
  {
    if (this != &src)
    {
      unsafe_reset(src.release());
    }

    return *this;
  }


  template <typename T>
  ArrayAutoPtr<T>::~ArrayAutoPtr() noexcept
  {
    unsafe_reset(0);
  }


  template <typename T>
  void
  swap(ArrayAutoPtr<T>& x, ArrayAutoPtr<T>& y) noexcept
  {
    x.swap(y);
  }

#if __GNUC__ == 4 && __GNUC_MINOR__ == 4
  template <typename T>
  void
  swap(ArrayAutoPtr<T>&& x, ArrayAutoPtr<T>& y) noexcept
  {
    x.swap(y);
  }

  template <typename T>
  void
  swap(ArrayAutoPtr<T>& x, ArrayAutoPtr<T>&& y) noexcept
  {
    x.swap(y);
  }
#endif
}

#endif
