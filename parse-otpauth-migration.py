#!/usr/bin/env python

from otpauth_migration_pb2 import MigrationPayload
import google.protobuf.message
import binascii
import argparse
import base64


def str_enum(field_descriptor, value) -> dict:
    key = field_descriptor.camelcase_name
    value = field_descriptor.enum_type.values_by_number[value].name
    return {key: value}


def parse_otp_parameters(otp_parameter) -> dict:
    d = {}
    d["secret"] = base64.b32encode(otp_parameter.secret).decode("utf-8")
    d["name"] = otp_parameter.name
    d["issuer"] = otp_parameter.issuer
    for field_descriptor, value in otp_parameter.ListFields()[-3:]:
        d.update(str_enum(field_descriptor, value))
    return d


def print_otp_params(list_dict: list[dict]):
    for _dict in list_dict:
        first_key = True
        for key in _dict:
            value = _dict[key]
            if first_key:
                print("- ", end="")
            else:
                print("  ", end="")
            print(f"{key}: {value}")
            first_key = False


def main(args):
    for i, otpauth in enumerate(args.otpauths):
        print(f"Parsing parameter {i+1}...", end="")
        if otpauth.startswith("otpauth-migration://offline?data="):
            try:
                otpauth_data = base64.b64decode(otpauth[33:])
            except binascii.Error:
                print(" invalid/corrupted otpauth-migration data; skipping")
                continue
            if not otpauth_data:
                print(" empty otpauth-migration data; skipping")
                continue

            otpauth_msg = MigrationPayload()
            try:
                otpauth_msg.ParseFromString(otpauth_data)
            except google.protobuf.message.DecodeError:
                print(" invalid/corrupted otpauth-migration data; skipping")
                continue
            list_ = []
            for otp_parameter in otpauth_msg.otp_parameters:
                list_.append(parse_otp_parameters(otp_parameter))
            print(" OK")
            print()
            print_otp_params(list_)
        else:
            print(" invalid format; skipping")
        print()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("otpauths", nargs="+")
    main(ap.parse_args())
