import { Column, Entity, Generated, Index, PrimaryGeneratedColumn, Unique } from 'typeorm';

@Entity()
@Index(["documentId", "isCurrent"])
export class EncryptedDocument {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({ unique: true })
    @Index()
    type: string;

    @Column({ type: "timestamp" })
    @Index()
    createdAt: Date;

    @Column()
    payload: string;
}
