#!/usr/bin/env bash
set -euo pipefail

if (($# < 1)); then
  echo "usage: $0 COMPILER [COMPILER_ARGS...]" >&2
  exit 64
fi
compiler=$1
shift

if [[ ${1:-} == --cmake-launcher ]]; then
  (($# >= 2)) || {
    echo "missing compiler argument after --cmake-launcher" >&2
    exit 64
  }
  shift 2
fi

isCompile=0
isAssembly=0
sourceFile=
outputFile=
optimizationFlag=-O0
compilerArgs=()

while (($#)); do
  arg=$1
  shift
  case "$arg" in
    -c)
      isCompile=1
      compilerArgs+=("$arg")
      ;;
    *.s|*.S)
      isAssembly=1
      sourceFile=$arg
      compilerArgs+=("$arg")
      ;;
    *.c|*.cc|*.cpp|*.cxx|*.C|*.i|*.ii|*.ll|*.bc)
      sourceFile=$arg
      compilerArgs+=("$arg")
      ;;
    -o)
      (($#)) || {
        echo "missing argument after -o" >&2
        exit 64
      }
      outputFile=$1
      compilerArgs+=("$arg" "$outputFile")
      shift
      ;;
    -o?*)
      outputFile=${arg#-o}
      compilerArgs+=("$arg")
      ;;
    -O*)
      optimizationFlag=$arg
      compilerArgs+=("$arg")
      ;;
    *)
      compilerArgs+=("$arg")
      ;;
  esac
done

if ((!isCompile)) || [[ -z $sourceFile ]]; then
  exec "$compiler" "${compilerArgs[@]}"
fi
if [[ -z $outputFile ]]; then
  outputFile=${sourceFile##*/}
  outputFile=${outputFile%.*}.o
fi

compute_payload_ordinal() {
  local namespace=${ATFIELD_PAYLOAD_NAMESPACE:?ATFIELD_PAYLOAD_NAMESPACE is required}
  local sourceRoot=${ATFIELD_SOURCE_ROOT:-}
  local upstreamRoot=${ATFIELD_UPSTREAM_SOURCE_ROOT:-}
  local sourcePath
  sourcePath=$(realpath -m -- "$sourceFile")
  local logicalSource
  if [[ -n $sourceRoot && $sourcePath == "$sourceRoot/"* ]]; then
    logicalSource=${sourcePath#"$sourceRoot/"}
  elif [[ -n $upstreamRoot && $sourcePath == "$upstreamRoot/"* ]]; then
    logicalSource="upstream/${ATFIELD_UPSTREAM_PACKAGE:?ATFIELD_UPSTREAM_PACKAGE is required}/${sourcePath#"$upstreamRoot/"}"
  elif [[ $sourcePath == /nix/store/* ]]; then
    local nixPath=${sourcePath#/nix/store/}
    local storeName=${nixPath%%/*}
    local logicalPackage=${storeName#*-}
    logicalSource="nix-store/$logicalPackage/${nixPath#"$storeName/"}"
  elif [[ $sourcePath == /* ]]; then
    logicalSource=generated/${sourceFile##*/}
  else
    logicalSource=$sourcePath
  fi
  local payloadName="$namespace/$logicalSource"
  local payloadHash
  payloadHash=$(printf "%s" "$payloadName" | sha256sum)
  payloadHash=${payloadHash:0:16}
  printf -v payloadOrdinal "%u" "0x$payloadHash"
}

scriptDir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

if ((isAssembly)); then
  "$compiler" "${compilerArgs[@]}"
  case ${ATFIELD_ANCHOR_PREPARATION:-0} in
    0) ;;
    1)
      compute_payload_ordinal
      injector=${ATFIELD_NATIVE_ANCHORS:-$scriptDir/../anchor/inject-native-anchors.py}
      "${ATFIELD_PYTHON:-python3}" "$injector" "$outputFile" "$payloadOrdinal"
      ;;
    *)
      echo "ATFIELD_ANCHOR_PREPARATION must be 0 or 1" >&2
      exit 64
      ;;
  esac
  if [[ ${ATFIELD_FIELD_BOUNDARY:-0} == 1 ]]; then
    printf "{\n  \"schema\": \"atfield-fields-v1\",\n  \"fields\": [],\n  \"selectors\": []\n}\n" > "$outputFile.field.json"
  fi
  exit 0
fi

case "$optimizationFlag" in
  -O0) backendOptimization=0 ;;
  -O1|-Og) backendOptimization=1 ;;
  -O2|-Os|-Oz) backendOptimization=2 ;;
  -O3|-Ofast) backendOptimization=3 ;;
  *)
    echo "unsupported backend optimization flag: $optimizationFlag" >&2
    exit 64
    ;;
esac

outputDir=$(dirname "$outputFile")
mkdir -p "$outputDir"
sourceBitcode=$(mktemp "$outputDir/.llvm-bc.XXXXXX.bc")
boundaryBitcode=$(mktemp "$outputDir/.llvm-boundary.XXXXXX.bc")
boundaryAsm=$(mktemp "$outputDir/.llvm-boundary.XXXXXX.s")
temporaryObject=$(mktemp "$outputDir/.llvm-object.XXXXXX.o")
trap 'rm -f -- "$sourceBitcode" "$boundaryBitcode" "$boundaryAsm" "$temporaryObject"' EXIT

irGenerationArgs=()
skipNext=0
for ((index = 0; index < ${#compilerArgs[@]}; index++)); do
  arg=${compilerArgs[index]}
  if ((skipNext)); then
    skipNext=0
    continue
  fi
  case "$arg" in
    -c)
      ;;
    -o)
      skipNext=1
      ;;
    *)
      irGenerationArgs+=("$arg")
      ;;
  esac
done

"$compiler" -D_LIBCPP_SGX_CONFIG= "${irGenerationArgs[@]}" -mno-red-zone \
  -c -emit-llvm -o "$sourceBitcode"

llc=${ATFIELD_LLC:-}
[[ -x $llc ]] || {
  echo "ATFIELD_LLC must point to executable atfield llc" >&2
  exit 64
}
anchorArgs=()
case ${ATFIELD_ANCHOR_PREPARATION:-0} in
  0)
    ;;
  1)
    compute_payload_ordinal
    anchorArgs=(-atfield-anchor-preparation "-atfield-payload-ordinal=$payloadOrdinal")
    ;;
  *)
    echo "ATFIELD_ANCHOR_PREPARATION must be 0 or 1" >&2
    exit 64
    ;;
esac

if [[ ${ATFIELD_FIELD_BOUNDARY:-0} == 1 ]]; then
  compute_payload_ordinal
  fieldTool=${ATFIELD_FIELD_TOOL:-$scriptDir/../field/.build-host/atfield-field}
  "$fieldTool" ir \
    --payload-ordinal "$payloadOrdinal" \
    --input "$sourceBitcode" \
    --output "$boundaryBitcode" \
    --manifest "$outputFile.field.json"
  "$llc" -filetype=asm -mtriple=x86_64-unknown-linux-gnu \
    -relocation-model=pic "-O=$backendOptimization" \
    -function-sections -data-sections "${anchorArgs[@]}" \
    "$boundaryBitcode" -o "$boundaryAsm"
  "$fieldTool" asm \
    --manifest "$outputFile.field.json" \
    --input "$boundaryAsm" \
    --output "$temporaryObject"
else
  "$llc" -filetype=obj -mtriple=x86_64-unknown-linux-gnu \
    -relocation-model=pic "-O=$backendOptimization" \
    -function-sections -data-sections "${anchorArgs[@]}" \
    "$sourceBitcode" -o "$temporaryObject"
fi
mv -f -- "$temporaryObject" "$outputFile"
