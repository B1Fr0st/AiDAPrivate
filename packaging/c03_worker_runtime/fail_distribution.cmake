if(NOT DEFINED AIDA_C03_DISTRIBUTION_BLOCKER OR AIDA_C03_DISTRIBUTION_BLOCKER STREQUAL "")
    message(FATAL_ERROR "AiDA C03 distribution gate was invoked without a blocker identity")
endif()
message(FATAL_ERROR "AiDA C03 distribution is unavailable: ${AIDA_C03_DISTRIBUTION_BLOCKER}")
