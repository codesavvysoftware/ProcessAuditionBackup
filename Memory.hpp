#pragma once
#ifndef MEMORY_HPP
#    define MEMORY_HPP
#    include "Precompiled.hpp"

class ProcessHeapObject
{
  public:
    ProcessHeapObject(SIZE_T);
    operator PBYTE() const { return (PBYTE)m_allocationPointer; }
    ~ProcessHeapObject();

  private:
    LPVOID m_allocationPointer;
    SIZE_T m_sizeInBytes;
};

#endif // MEMORY_HPP
