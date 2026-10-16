#ifndef TEST_APR_OPTIONAL_H
#define TEST_APR_OPTIONAL_H
#define APR_DECLARE_OPTIONAL_FN(ret,name,args) typedef ret (*apr_OFN_##name##_t) args
#define APR_REGISTER_OPTIONAL_FN(name) do { (void)&name; } while (0)
#endif
