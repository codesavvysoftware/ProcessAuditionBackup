// clang-format off
 #include "Precompiled.hpp"
 #include "WinBase.hpp"
 #include "Memory.hpp"
// clang-format on

using namespace std;

ProcessHeapObject::ProcessHeapObject(SIZE_T sizeInBytes) : m_sizeInBytes(sizeInBytes)
{
    m_allocationPointer = HeapAlloc(GetProcessHeap(), 0, m_sizeInBytes);
    if (NULL == m_allocationPointer) {
        throw runtime_error("Process Heap Allocation Failed!");
    }
}

ProcessHeapObject::~ProcessHeapObject()
{
    if (NULL != m_allocationPointer) {
        HeapFree(GetProcessHeap(), 0, m_allocationPointer);
    }
}
