#pragma once

#include <mlibc/allocator.hpp>

#include <cstddef>

// template class implementing a reference-counted pointer to a given type
template <typename T>
class Rc {
    struct RefCounted {
        size_t refcount;
        T value;

        RefCounted(auto&&... args) : refcount{1}, value{std::forward<decltype(args)>(args)...} {}
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
    Rc(std::nullptr_t) : ptr(nullptr) {}

    static auto make(auto&&... args) -> Rc<T>{
        RefCounted* ptr = static_cast<RefCounted*>(getAllocator().allocate(sizeof(RefCounted)));
        ::new (ptr) RefCounted{std::forward<decltype(args)>(args)...};
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

    bool operator==(std::nullptr_t) const {
        return ptr == nullptr;
    }

    bool operator!=(std::nullptr_t) const {
        return ptr != nullptr;
    }

    explicit operator bool() const {
        return ptr != nullptr;
    }
};
