import { Module } from '@nestjs/common';
import { CategoriesController, ProductsController } from './products.controller';
import { ReviewsController } from './reviews.controller';

@Module({ controllers: [CategoriesController, ProductsController, ReviewsController] })
export class AppModule {}
