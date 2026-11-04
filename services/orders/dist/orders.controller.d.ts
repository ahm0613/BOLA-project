export declare class OrdersController {
    listMine(req: any): Promise<any[]>;
    getOrder(req: any, id: number): Promise<any>;
    cancel(req: any, id: number): Promise<any>;
    updateMemo(req: any, id: number, body: {
        memo: string;
    }): Promise<any>;
}
