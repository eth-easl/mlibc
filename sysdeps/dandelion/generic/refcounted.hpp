#pragma once

#include <mlibc/allocator.hpp>

#include <cstddef>

// template class implementing a reference-counted pointer to a given type
template <typename T>
class Rc {
    struct RefCounted {
        T value;
        size_t refcount;
    };

    RefCounted *ptr;
    Rc(RefCounted *ptr) : ptr(ptr) {}


    void maybe_destroy() {
        if (ptr) {
            ptr->refcount--;
            if (ptr->refcount == 0) {
                ptr->~RefCounted();
                getAllocator().deallocate(ptr, sizeof(RefCounted));
            }
        }
    }
public:
    Rc() : ptr(nullptr) {}
    Rc(nullptr_t) : ptr(nullptr) {}

    template <typename... Args>
    static auto make(Args&&... args) -> Rc<T>{
        RefCounted* ptr = getAllocator().allocate(sizeof(RefCounted));
        ::new (ptr) RefCounted{std::forward<Args>(args)..., 1};
        return Rc<T>(ptr);
    }

    Rc(const Rc& other) : ptr(other.ptr) {
        if (ptr) {
            ptr->refcount++;
        }
    }

    Rc(Rc&& other) : ptr(other.ptr) {
        other.ptr = nullptr;
    }

    ~Rc() {
        this->maybe_destroy();
    }

    Rc& operator=(const Rc& other) {
        this->maybe_destroy();
        ptr = other.ptr;
        if (ptr) {
            ptr->refcount++;
        }
        return *this;
    }

    Rc& operator=(Rc&& other) {
        this->maybe_destroy();
        ptr = other.ptr;
        other.ptr = nullptr;
        return *this;
    }

    T* get() const {
        return &ptr->value;
    }

    T& operator*() {
        return ptr->value;
    }

    T* operator->() {
        return this->get();
    }

    bool operator==(const Rc& other) const {
        return ptr == other.ptr;
    }

    bool operator!=(const Rc& other) const {
        return ptr != other.ptr;
    }

    bool operator==(nullptr_t) const {
        return ptr == nullptr;
    }

    bool operator!=(nullptr_t) const {
        return ptr != nullptr;
    }

    explicit operator bool() const {
        return ptr != nullptr;
    }
};