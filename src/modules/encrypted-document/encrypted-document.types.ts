import { FindManyOptions, FindOptionsOrder, FindOptionsWhere } from "typeorm";
import { EncryptedDocument } from "./encrypted-document.entity";

export type PayloadFieldType = string | string[] | number | number[] | boolean | null;
export type Payload<T = unknown> = Record<keyof T, PayloadFieldType>;

export type ScanCallback = (documents: EncryptedDocument[]) => Promise<boolean>;
export type ScanOptions = {
    recordFilter?: FindOptionsWhere<EncryptedDocument>[] | FindOptionsWhere<EncryptedDocument>;
    documentFilter?: string;
    after?: number;
    take?: number;
}

export type DecryptedDocument<TPayload = unknown> = Omit<EncryptedDocument, "payload" | "dekId"> & {
    payload: TPayload;
}