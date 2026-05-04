# Multi-stage build: a minimal runtime image that only contains the
# mirage binary and the libstdc++ runtime it needs.
FROM debian:bookworm-slim AS build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential cmake ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
COPY tests ./tests
COPY bench ./bench

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j --target mirage && \
    ctest --test-dir build --output-on-failure

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends libstdc++6 ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --create-home --uid 10001 mirage

COPY --from=build /src/build/mirage /usr/local/bin/mirage

USER mirage
WORKDIR /home/mirage

EXPOSE 55432

ENTRYPOINT ["/usr/local/bin/mirage"]
CMD ["--host", "0.0.0.0", "--port", "55432", "--audit-log", "/home/mirage/audit.jsonl"]
