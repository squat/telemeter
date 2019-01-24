#!/bin/bash -e

# Runs a series of e2e tests with the mock authorization server
# and the Telemeter server. These tests verify that the server will
# properly rate-limit both authorized and unauthorized clients, as well
# as accept and federate only whitelisted metrics.

trap 'exit 0' INT TERM
# shellcheck disable=SC2154
trap 'rv=$?; kill $(jobs -p); exit $rv' INT TERM EXIT

./authorization-server localhost:9001 ./test/tokens.json &

./telemeter-server \
        --ttl=24h \
        --ratelimit=5m \
        --authorize http://localhost:9001 \
        --name instance-0 \
        --shared-key=test/test.key \
        --listen localhost:9003 \
        --listen-internal localhost:9004 \
        --whitelist '{_id=~".*success"}' &

sleep 1

ratelimit_auth() {
    local expected=4
    local attempts=5
    local fails=0
    while [ $attempts -gt 0 ]; do 
        if [ "$(curl http://localhost:9003/authorize -XPOST -H "Authorization: Bearer a" -d "id=${FUNCNAME[0]}" --silent --write-out '%{http_code}' --output /dev/null)" -eq 429 ]; then
            fails=$((fails+1))
        fi
        attempts=$((attempts-1))
        sleep 1
    done
    if [ $fails -eq $expected ]; then
        return 0
    fi
    printf "\tFAIL: %s expected %d limited requests, got %d\n" "${FUNCNAME[0]}" $expected $fails
    return 1
}

ratelimit_post() {
    local timestamp
    timestamp=$(date +%s%N | cut -b1-13)

    local id=${FUNCNAME[0]}
    local metrics="
    up{_id=\"$id\"} 1 $timestamp
    "

    local jwt
    if ! jwt="$(curl http://localhost:9003/authorize -XPOST -H "Authorization: Bearer a" -d "id=$id" --silent --fail | jq -r '.token')" ; then
        printf "\tFAIL: %s failed to authorize and get JWT\n" "${FUNCNAME[0]}"
        return 1
    fi

    local expected=4
    local attempts=5
    local fails=0
    while [ $attempts -gt 0 ]; do 
        if [ "$(curl http://localhost:9003/upload?id="$id" -XPOST -H "Authorization: Bearer $jwt" -H "Content-Type: text/plain" --data "$metrics" --silent --write-out '%{http_code}' --output /dev/null)" -eq 429 ]; then
            fails=$((fails+1))
        fi
        attempts=$((attempts-1))
        sleep 1
    done
    if [ $fails -eq $expected ]; then
        return 0
    fi
    printf "\tFAIL: %s expected %d limited requests, got %d\n" "${FUNCNAME[0]}" $expected $fails
    return 1
}

success_post() {
    local timestamp
    timestamp=$(date +%s%N | cut -b1-13)

    local metrics1="
    up{_id=\"1\"} 1 $timestamp
    "
    local metrics2="
    up{_id=\"2\"} 1 $timestamp
    "
    local metrics3="
    up{_id=\"3\"} 1 $timestamp
    "

    local jwt1
    local jwt2
    local jwt3
    if ! jwt1="$(curl http://localhost:9003/authorize -XPOST -H "Authorization: Bearer a" -d "id=1" --silent --fail | jq -r '.token')" ; then
        printf "\tFAIL: %s failed to authorize and get JWT\n" "${FUNCNAME[0]}"
        return 1
    fi
    if ! jwt2="$(curl http://localhost:9003/authorize -XPOST -H "Authorization: Bearer a" -d "id=2" --silent --fail | jq -r '.token')" ; then
        printf "\tFAIL: %s failed to authorize and get JWT\n" "${FUNCNAME[0]}"
        return 1
    fi
    if ! jwt3="$(curl http://localhost:9003/authorize -XPOST -H "Authorization: Bearer a" -d "id=3" --silent --fail | jq -r '.token')" ; then
        printf "\tFAIL: %s failed to authorize and get JWT\n" "${FUNCNAME[0]}"
        return 1
    fi

    local fails=0
    local expected=0
    if [ "$(curl http://localhost:9003/upload?id=1 -XPOST -H "Authorization: Bearer $jwt1" -H "Content-Type: text/plain" --data "$metrics1" --silent --write-out '%{http_code}' --output /dev/null)" -eq 429 ]; then
        fails=$((fails+1))
    fi
    if [ "$(curl http://localhost:9003/upload?id=2 -XPOST -H "Authorization: Bearer $jwt2" -H "Content-Type: text/plain" --data "$metrics2" --silent --write-out '%{http_code}' --output /dev/null)" -eq 429 ]; then
        fails=$((fails+1))
    fi
    if [ "$(curl http://localhost:9003/upload?id=3 -XPOST -H "Authorization: Bearer $jwt3" -H "Content-Type: text/plain" --data "$metrics3" --silent --write-out '%{http_code}' --output /dev/null)" -eq 429 ]; then
        fails=$((fails+1))
    fi

    if [ $fails -eq $expected ]; then
        return 0
    fi
    printf "\tFAIL: %s expected %d limited requests, got %d\n" "${FUNCNAME[0]}" $expected $fails
    return 1
}

auth_post_scrape_empty() {
    local timestamp
    timestamp=$(date +%s%N | cut -b1-13)

    local id=${FUNCNAME[0]}

    local metrics="
    up{_id=\"$id\"} 1 $timestamp
    "

    local jwt
    if ! jwt="$(curl http://localhost:9003/authorize -XPOST -H "Authorization: Bearer a" -d "id=$id" --silent --fail | jq -r '.token')" ; then
        printf "\tFAIL: %s failed to authorize and get JWT\n" "${FUNCNAME[0]}"
        return 1
    fi

    if ! curl http://localhost:9003/upload?id="$id" -XPOST -H "Authorization: Bearer $jwt" -H "Content-Type: text/plain" --data "$metrics" --silent --fail ; then
        printf "\tFAIL: %s failed to post metrics\n" "${FUNCNAME[0]}"
        return 1
    fi

    local matching
    if ! matching="$(curl http://localhost:9004/federate --silent --fail)" ; then
        printf "\tFAIL: %s failed to scrape metrics\n" "${FUNCNAME[0]}"
        return 1
    fi
    # Do this in a separate step so we can ignore the a non-matching
    # status code while still capturing errors from cURL.
    matching=$(echo "$matching" | grep "$id" -c || :)

    if [ "$matching" -eq 0 ]; then
        return 0
    fi
    printf "\tFAIL: %s expected no matching metrics, got %d\n" "${FUNCNAME[0]}" "$matching"
    return 1
}

auth_post_scrape_success() {
    local timestamp
    timestamp=$(date +%s%N | cut -b1-13)

    local id=${FUNCNAME[0]}

    local metrics="
    up{_id=\"$id\"} 1 $timestamp
    ALERTS{_id=\"$id\",alertstate=\"firing\"} 10 $timestamp
    "

    local jwt
    if ! jwt="$(curl http://localhost:9003/authorize -XPOST -H "Authorization: Bearer a" -d "id=$id" --silent --fail | jq -r '.token')" ; then
        printf "\tFAIL: %s failed to authorize and get JWT\n" "${FUNCNAME[0]}"
        return 1
    fi

    if ! curl http://localhost:9003/upload?id="$id" -XPOST -H "Authorization: Bearer $jwt" -H "Content-Type: text/plain" --data "$metrics" --silent --fail ; then
        printf "\tFAIL: %s failed to post metrics\n" "${FUNCNAME[0]}"
        return 1
    fi

    local expected=2
    local matching
    if ! matching="$(curl http://localhost:9004/federate --silent --fail | grep "$id" -c)" ; then
        printf "\tFAIL: %s failed to scrape metrics\n" "${FUNCNAME[0]}"
        return 1
    fi

    if [ "$matching" -eq "$expected" ]; then
        return 0
    fi
    printf "\tFAIL: %s expected %d matching metrics, got %d\n" "${FUNCNAME[0]}" "$expected" "$matching"
    return 1
}

tests=0
fails=0
! ratelimit_auth && fails=$((fails+1)) ; tests=$((tests+1))
! ratelimit_post && fails=$((fails+1)) ; tests=$((tests+1))
! success_post && fails=$((fails+1)) ; tests=$((tests+1))
! auth_post_scrape_empty && fails=$((fails+1)) ; tests=$((tests+1))
! auth_post_scrape_success && fails=$((fails+1)) ; tests=$((tests+1))

printf "%d tests\n" $tests
printf "%d failures\n" $fails
exit $fails
