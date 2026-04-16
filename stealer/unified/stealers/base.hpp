#pragma once

class AbstractStealer {
public:
    virtual ~AbstractStealer() = default;
    virtual void steal() = 0;
};
