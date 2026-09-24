import { z } from "zod";
import { and, eq } from "drizzle-orm";
import { createTRPCRouter, protectedProcedure } from "../trpc";
import { db, quadros, cartoes, membrosQuadro } from "../db";
import { verificarAcessoAoQuadro } from "./acesso";
import { serviceRoleClient } from "./cliente-servidor";

export const quadrosRouter = createTRPCRouter({
  apagarCartao: protectedProcedure
    .input(z.object({ cartaoId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      await ctx.db.delete(cartoes).where(eq(cartoes.id, input.cartaoId));
    }),

  lerQuadro: protectedProcedure
    .input(z.object({ quadroId: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      return ctx.db.query.quadros.findFirst({ where: eq(quadros.id, input.quadroId) });
    }),

  renomearQuadro: protectedProcedure
    .input(z.object({ quadroId: z.string().uuid(), nome: z.string() }))
    .mutation(async ({ ctx, input }) => {
      await verificarAcessoAoQuadro(ctx.db, ctx.user.id, input.quadroId);
      await ctx.db.update(quadros).set({ nome: input.nome }).where(eq(quadros.id, input.quadroId));
    }),

  sairDoQuadro: protectedProcedure
    .input(z.object({ quadroId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      await ctx.db
        .delete(membrosQuadro)
        .where(and(eq(membrosQuadro.quadroId, input.quadroId), eq(membrosQuadro.userId, ctx.user.id)));
    }),

  arquivarCartao: protectedProcedure
    .input(z.object({ cartaoId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      await ctx.supabase.from("cartoes").update({ arquivado: true }).eq("id", input.cartaoId);
    }),

  expurgarCartao: protectedProcedure
    .input(z.object({ cartaoId: z.string().uuid() }))
    .mutation(async ({ input }) => {
      await serviceRoleClient.from("cartoes").delete().eq("id", input.cartaoId);
    }),

  contarCartoes: protectedProcedure
    .input(z.object({ quadroId: z.string().uuid() }))
    .mutation(async ({ input }) => {
      return { quadroId: input.quadroId, total: 0 };
    }),
});
