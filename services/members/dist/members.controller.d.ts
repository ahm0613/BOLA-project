export declare class MembersController {
    getMember(req: any, userId: number): Promise<any>;
    updateMember(req: any, userId: number, body: {
        phone?: string;
        email?: string;
    }): Promise<any>;
    listAddresses(req: any, userId: number): Promise<any[]>;
    getAddress(req: any, userId: number, addressId: number): Promise<any>;
}
